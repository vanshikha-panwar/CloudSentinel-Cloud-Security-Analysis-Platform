"""
Scan Service Module

Runs the existing RuleEngine against IAM data that has already been loaded
into Python and returns an API-ready report dictionary.

This module is side-effect free:
- no file writes
- no stdout output
- no AWS calls (data collection stays in scanner.iam_collector)

The report shape mirrors ReportGenerator.save_json_report() so API responses
and CLI JSON reports stay interchangeable. Each finding keeps all of its
existing fields and gains a stable finding_id.
"""

import hashlib
import re
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional, Tuple

from scanner.rule_engine import RuleEngine

# Same ranking as main.filter_findings (duplicated to avoid importing the CLI)
SEVERITY_ORDER = {"CRITICAL": 4, "HIGH": 3, "MEDIUM": 2, "LOW": 1, "INFO": 0}

# Same choices the CLI accepts for --entity-type
ENTITY_TYPES = ("USER", "ROLE", "GROUP", "ACCOUNT")

FINDING_ID_PREFIX = "fnd_"

# Standalone numbers in descriptions (e.g. "240 days") change between scans
# of the same misconfiguration, so they are masked before hashing.
_VOLATILE_NUMBER = re.compile(r"\b\d+\b")


def _normalize_severity(min_severity: Optional[str]) -> Optional[str]:
    if min_severity is None:
        return None
    value = str(min_severity).upper()
    if value not in SEVERITY_ORDER:
        raise ValueError(
            f"Invalid min_severity '{min_severity}'. Expected one of: {', '.join(SEVERITY_ORDER)}"
        )
    return value


def _normalize_entity_type(entity_type: Optional[str]) -> Optional[str]:
    if entity_type is None:
        return None
    value = str(entity_type).upper()
    if value not in ENTITY_TYPES:
        raise ValueError(
            f"Invalid entity_type '{entity_type}'. Expected one of: {', '.join(ENTITY_TYPES)}"
        )
    return value


def validate_filters(
    min_severity: Optional[str] = None,
    entity_type: Optional[str] = None,
) -> Tuple[Optional[str], Optional[str]]:
    """Return upper-cased filter values. Raises ValueError on invalid values."""
    return _normalize_severity(min_severity), _normalize_entity_type(entity_type)


def filter_findings(
    findings: List[Dict[str, Any]],
    min_severity: Optional[str] = None,
    entity_type: Optional[str] = None,
) -> List[Dict[str, Any]]:
    """
    Apply severity / entity-type filters to findings.

    Matches main.filter_findings behavior for valid values. Unlike the CLI
    (where argparse restricts choices), invalid values raise ValueError
    instead of being silently treated as INFO. Values are case-insensitive.
    """
    min_severity = _normalize_severity(min_severity)
    entity_type = _normalize_entity_type(entity_type)
    filtered = findings

    if min_severity:
        min_rank = SEVERITY_ORDER[min_severity]
        filtered = [f for f in filtered if SEVERITY_ORDER.get(f.get("severity", "INFO"), 0) >= min_rank]

    if entity_type:
        filtered = [f for f in filtered if f.get("entity_type") == entity_type]

    return filtered


def compute_finding_id(finding: Dict[str, Any], account_id: str) -> str:
    """
    Return a deterministic ID for a finding.

    Derived from account_id, rule_id, entity_type, affected_entity and the
    description with standalone numbers masked, so the same misconfiguration
    keeps the same ID across rescans even as day counts change.
    """
    description = _VOLATILE_NUMBER.sub("#", str(finding.get("description", "")))
    key = "|".join([
        str(account_id),
        str(finding.get("rule_id", "")),
        str(finding.get("entity_type", "")),
        str(finding.get("affected_entity", "")),
        description,
    ])
    digest = hashlib.sha256(key.encode("utf-8")).hexdigest()[:16]
    return f"{FINDING_ID_PREFIX}{digest}"


def _severity_counts(findings: List[Dict[str, Any]]) -> Dict[str, int]:
    return {
        "total_findings": len(findings),
        "critical": sum(1 for f in findings if f.get("severity") == "CRITICAL"),
        "high": sum(1 for f in findings if f.get("severity") == "HIGH"),
        "medium": sum(1 for f in findings if f.get("severity") == "MEDIUM"),
        "low": sum(1 for f in findings if f.get("severity") == "LOW"),
    }


class ScanService:
    """
    Stateless orchestration of the existing scanner rule engine.

    A single instance can be reused across scans (e.g. one per API process),
    so rules_config.json is loaded once rather than per request.
    """

    def __init__(self, engine: Optional[RuleEngine] = None):
        self.engine = engine or RuleEngine()
        self.mitre_mapper = self.engine.mitre_mapper

    def _assign_finding_ids(self, findings: List[Dict[str, Any]], account_id: str) -> List[Dict[str, Any]]:
        """
        Return copies of findings with finding_id added.
        Colliding IDs within one scan get a deterministic "-N" suffix
        based on rule engine output order.
        """
        seen: Dict[str, int] = {}
        result = []
        for finding in findings:
            base_id = compute_finding_id(finding, account_id)
            count = seen.get(base_id, 0)
            seen[base_id] = count + 1
            finding_id = base_id if count == 0 else f"{base_id}-{count + 1}"
            result.append({"finding_id": finding_id, **finding})
        return result

    def run_scan(
        self,
        iam_data: Dict[str, Any],
        min_severity: Optional[str] = None,
        entity_type: Optional[str] = None,
    ) -> Dict[str, Any]:
        """
        Run all rules against pre-loaded IAM data and build a report dict.

        Args:
            iam_data: Dict in the IamCollector.collect_all() / load_from_file() shape.
            min_severity: Optional minimum severity (CRITICAL/HIGH/MEDIUM/LOW/INFO).
            entity_type: Optional entity filter (USER/ROLE/GROUP/ACCOUNT).

        Returns:
            Report dict with scan_metadata, filters, summary,
            mitre_attack_summary and findings (sorted by cvss_score desc).

        Raises:
            TypeError: iam_data is not a dict.
            ValueError: invalid filter value.
        """
        if not isinstance(iam_data, dict):
            raise TypeError(f"iam_data must be a dict, got {type(iam_data).__name__}")

        # Validate filters before doing any work
        min_severity, entity_type = validate_filters(min_severity, entity_type)

        account_id = str(iam_data.get("account_id") or "UNKNOWN")
        scan_time = iam_data.get("scan_time") or datetime.now(timezone.utc).isoformat()
        if isinstance(scan_time, datetime):
            scan_time = scan_time.isoformat()

        all_findings = self.engine.run_all_rules(iam_data)

        # IDs are assigned before filtering so they don't depend on filters
        all_findings = self._assign_finding_ids(all_findings, account_id)
        findings = filter_findings(all_findings, min_severity, entity_type)

        # Same ordering as the CLI JSON report (stable sort keeps engine order on ties)
        findings = sorted(findings, key=lambda f: f.get("cvss_score", 0), reverse=True)

        for finding in findings:
            if not finding.get("mitre_attack"):
                finding["mitre_attack"] = self.mitre_mapper.get_mapping(finding.get("rule_id", ""))

        return {
            "scan_metadata": {
                "account_id": account_id,
                "scan_time": scan_time,
                "total_entities_scanned": {
                    "users": len(iam_data.get("users") or []),
                    "roles": len(iam_data.get("roles") or []),
                    "groups": len(iam_data.get("groups") or []),
                },
                "frameworks": ["Custom IAM Rules", "MITRE ATT&CK"],
            },
            "filters": {
                "min_severity": min_severity,
                "entity_type": entity_type,
                "total_findings_before_filter": len(all_findings),
            },
            "summary": _severity_counts(findings),
            "mitre_attack_summary": self.mitre_mapper.summarize_findings(findings),
            "findings": findings,
        }
