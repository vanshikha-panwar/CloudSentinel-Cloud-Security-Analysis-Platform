"""
MITRE ATT&CK Mapping Module

Maps IAM scanner rule IDs to MITRE ATT&CK techniques and tactics.
Uses Enterprise ATT&CK (including cloud sub-techniques) to help
security teams correlate IAM misconfigurations with adversary behaviors.

Reference: https://attack.mitre.org/
"""

from typing import Dict, List, Any, Optional
import os
import json


# Technique catalog used by this scanner (subset of ATT&CK relevant to IAM/cloud)
TECHNIQUES: Dict[str, Dict[str, Any]] = {
    "T1078": {
        "technique_id": "T1078",
        "technique_name": "Valid Accounts",
        "tactics": ["Initial Access", "Persistence", "Privilege Escalation", "Defense Evasion"],
        "url": "https://attack.mitre.org/techniques/T1078/"
    },
    "T1078.004": {
        "technique_id": "T1078.004",
        "technique_name": "Valid Accounts: Cloud Accounts",
        "tactics": ["Initial Access", "Persistence", "Privilege Escalation", "Defense Evasion"],
        "url": "https://attack.mitre.org/techniques/T1078/004/"
    },
    "T1098": {
        "technique_id": "T1098",
        "technique_name": "Account Manipulation",
        "tactics": ["Persistence", "Privilege Escalation"],
        "url": "https://attack.mitre.org/techniques/T1098/"
    },
    "T1098.001": {
        "technique_id": "T1098.001",
        "technique_name": "Account Manipulation: Additional Cloud Credentials",
        "tactics": ["Persistence", "Privilege Escalation"],
        "url": "https://attack.mitre.org/techniques/T1098/001/"
    },
    "T1098.003": {
        "technique_id": "T1098.003",
        "technique_name": "Account Manipulation: Additional Cloud Roles",
        "tactics": ["Persistence", "Privilege Escalation"],
        "url": "https://attack.mitre.org/techniques/T1098/003/"
    },
    "T1110": {
        "technique_id": "T1110",
        "technique_name": "Brute Force",
        "tactics": ["Credential Access"],
        "url": "https://attack.mitre.org/techniques/T1110/"
    },
    "T1136.003": {
        "technique_id": "T1136.003",
        "technique_name": "Create Account: Cloud Account",
        "tactics": ["Persistence"],
        "url": "https://attack.mitre.org/techniques/T1136/003/"
    },
    "T1199": {
        "technique_id": "T1199",
        "technique_name": "Trusted Relationship",
        "tactics": ["Initial Access"],
        "url": "https://attack.mitre.org/techniques/T1199/"
    },
    "T1530": {
        "technique_id": "T1530",
        "technique_name": "Data from Cloud Storage Object",
        "tactics": ["Collection"],
        "url": "https://attack.mitre.org/techniques/T1530/"
    },
    "T1548": {
        "technique_id": "T1548",
        "technique_name": "Abuse Elevation Control Mechanism",
        "tactics": ["Privilege Escalation", "Defense Evasion"],
        "url": "https://attack.mitre.org/techniques/T1548/"
    },
    "T1550": {
        "technique_id": "T1550",
        "technique_name": "Use Alternate Authentication Material",
        "tactics": ["Defense Evasion", "Lateral Movement"],
        "url": "https://attack.mitre.org/techniques/T1550/"
    },
    "T1552": {
        "technique_id": "T1552",
        "technique_name": "Unsecured Credentials",
        "tactics": ["Credential Access"],
        "url": "https://attack.mitre.org/techniques/T1552/"
    },
    "T1580": {
        "technique_id": "T1580",
        "technique_name": "Cloud Infrastructure Discovery",
        "tactics": ["Discovery"],
        "url": "https://attack.mitre.org/techniques/T1580/"
    },
}

# Primary mapping: scanner rule -> ATT&CK techniques (ordered by relevance)
RULE_MITRE_MAP: Dict[str, Dict[str, Any]] = {
    "RULE_001": {
        "technique_ids": ["T1078.004"],
        "primary_tactic": "Privilege Escalation",
        "rationale": (
            "Root without MFA is a high-value valid cloud account. Compromised root "
            "credentials enable full account takeover without a second factor."
        ),
    },
    "RULE_002": {
        "technique_ids": ["T1078.004"],
        "primary_tactic": "Initial Access",
        "rationale": (
            "Console users without MFA are easier targets for password-based initial "
            "access using valid cloud accounts."
        ),
    },
    "RULE_003": {
        "technique_ids": ["T1078.004", "T1098", "T1548"],
        "primary_tactic": "Privilege Escalation",
        "rationale": (
            "Action:* Resource:* grants unrestricted privileges, enabling adversaries "
            "to use valid accounts for account manipulation and elevation of privileges."
        ),
    },
    "RULE_004": {
        "technique_ids": ["T1078.004", "T1552"],
        "primary_tactic": "Credential Access",
        "rationale": (
            "Stale but active access keys are long-lived credentials that adversaries "
            "can reuse if leaked or stolen."
        ),
    },
    "RULE_005": {
        "technique_ids": ["T1078.004", "T1552"],
        "primary_tactic": "Credential Access",
        "rationale": (
            "Unrotated access keys increase the window of opportunity for credential "
            "theft and continued use of valid cloud accounts."
        ),
    },
    "RULE_006": {
        "technique_ids": ["T1078.004", "T1098"],
        "primary_tactic": "Privilege Escalation",
        "rationale": (
            "Wildcard inline policies create hard-to-audit admin-like privileges that "
            "support account manipulation and privilege abuse."
        ),
    },
    "RULE_007": {
        "technique_ids": ["T1078.004", "T1098.003", "T1548"],
        "primary_tactic": "Initial Access",
        "rationale": (
            "A trust policy with Principal:* lets any identity assume the role, enabling "
            "initial access and abuse of cloud role privileges."
        ),
    },
    "RULE_008": {
        "technique_ids": ["T1098", "T1098.001", "T1098.003", "T1136.003", "T1078.004"],
        "primary_tactic": "Privilege Escalation",
        "rationale": (
            "IAM actions such as CreatePolicyVersion, PassRole, AttachUserPolicy, and "
            "CreateAccessKey map directly to account manipulation and privilege escalation."
        ),
    },
    "RULE_009": {
        "technique_ids": ["T1110", "T1078"],
        "primary_tactic": "Credential Access",
        "rationale": (
            "Weak password policies make online password guessing and credential stuffing "
            "against valid accounts more practical."
        ),
    },
    "RULE_010": {
        "technique_ids": ["T1098", "T1078.004"],
        "primary_tactic": "Persistence",
        "rationale": (
            "Direct user policy attachments increase privilege sprawl and make account "
            "manipulation harder to detect during audits."
        ),
    },
    "RULE_011": {
        "technique_ids": ["T1199", "T1078.004", "T1098.003"],
        "primary_tactic": "Initial Access",
        "rationale": (
            "Cross-account role trust without ExternalId is vulnerable to confused-deputy "
            "abuse of trusted relationships and cloud roles."
        ),
    },
    "RULE_012": {
        "technique_ids": ["T1078.004", "T1530", "T1580"],
        "primary_tactic": "Collection",
        "rationale": (
            "Broad IAM/S3/EC2 permissions without conditions enable unrestricted discovery "
            "and collection from cloud resources once credentials are obtained."
        ),
    },
}


class MitreAttackMapper:
    """
    Resolves MITRE ATT&CK technique metadata for scanner rules.
    """

    def __init__(self, techniques: Optional[Dict[str, Dict]] = None,
                 rule_map: Optional[Dict[str, Dict]] = None):
        self.techniques = techniques or TECHNIQUES
        self.rule_map = rule_map or RULE_MITRE_MAP

    @classmethod
    def from_rules_config(cls, config_path: Optional[str] = None) -> "MitreAttackMapper":
        """
        Optionally enrich mappings from rules/rules_config.json if present.
        Falls back to built-in RULE_MITRE_MAP.
        """
        mapper = cls()
        if not config_path:
            base = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
            config_path = os.path.join(base, "rules", "rules_config.json")

        if not os.path.isfile(config_path):
            return mapper

        try:
            with open(config_path, "r", encoding="utf-8") as f:
                config = json.load(f)
        except (OSError, json.JSONDecodeError):
            return mapper

        for rule in config.get("rules", []):
            rule_id = rule.get("rule_id")
            mitre = rule.get("mitre_attack")
            if not rule_id or not mitre:
                continue
            # Overlay config-defined mapping onto defaults
            technique_ids = mitre.get("technique_ids") or [
                t.get("technique_id") for t in mitre.get("techniques", []) if t.get("technique_id")
            ]
            if technique_ids:
                mapper.rule_map[rule_id] = {
                    "technique_ids": technique_ids,
                    "primary_tactic": mitre.get("primary_tactic", mapper.rule_map.get(rule_id, {}).get("primary_tactic", "Unknown")),
                    "rationale": mitre.get("rationale", mapper.rule_map.get(rule_id, {}).get("rationale", "")),
                }
        return mapper

    def get_mapping(self, rule_id: str) -> Dict[str, Any]:
        """
        Return full MITRE ATT&CK block for a rule_id.

        Structure:
        {
          "framework": "MITRE ATT&CK",
          "primary_tactic": "...",
          "tactics": [...],
          "techniques": [{technique_id, technique_name, tactics, url}, ...],
          "rationale": "..."
        }
        """
        entry = self.rule_map.get(rule_id, {})
        technique_ids = entry.get("technique_ids", [])
        techniques = []
        tactics_set = set()

        for tid in technique_ids:
            tech = self.techniques.get(tid)
            if tech:
                techniques.append(dict(tech))
                for t in tech.get("tactics", []):
                    tactics_set.add(t)
            else:
                techniques.append({
                    "technique_id": tid,
                    "technique_name": "Unknown Technique",
                    "tactics": [],
                    "url": f"https://attack.mitre.org/techniques/{tid.replace('.', '/')}/"
                })

        primary = entry.get("primary_tactic")
        if primary:
            # Keep primary first in tactics list
            ordered_tactics = [primary] + sorted(t for t in tactics_set if t != primary)
        else:
            ordered_tactics = sorted(tactics_set)

        return {
            "framework": "MITRE ATT&CK",
            "primary_tactic": primary or (ordered_tactics[0] if ordered_tactics else "Unknown"),
            "tactics": ordered_tactics,
            "techniques": techniques,
            "rationale": entry.get("rationale", ""),
        }

    def format_short(self, rule_id: str) -> str:
        """Human-readable one-liner for terminal reports."""
        mapping = self.get_mapping(rule_id)
        if not mapping.get("techniques"):
            return "N/A"
        parts = [
            f"{t['technique_id']} ({t['technique_name']})"
            for t in mapping["techniques"]
        ]
        return f"{mapping['primary_tactic']} | " + "; ".join(parts)

    def summarize_findings(self, findings: List[Dict[str, Any]]) -> Dict[str, Any]:
        """
        Build ATT&CK coverage summary across a list of findings.
        """
        tactic_counts: Dict[str, int] = {}
        technique_counts: Dict[str, Dict[str, Any]] = {}

        for finding in findings:
            mitre = finding.get("mitre_attack") or self.get_mapping(finding.get("rule_id", ""))
            primary = mitre.get("primary_tactic")
            if primary:
                tactic_counts[primary] = tactic_counts.get(primary, 0) + 1
            for tech in mitre.get("techniques", []):
                tid = tech.get("technique_id", "UNKNOWN")
                if tid not in technique_counts:
                    technique_counts[tid] = {
                        "technique_id": tid,
                        "technique_name": tech.get("technique_name", ""),
                        "url": tech.get("url", ""),
                        "count": 0,
                    }
                technique_counts[tid]["count"] += 1

        techniques_sorted = sorted(
            technique_counts.values(),
            key=lambda x: (-x["count"], x["technique_id"])
        )
        tactics_sorted = sorted(
            [{"tactic": k, "count": v} for k, v in tactic_counts.items()],
            key=lambda x: (-x["count"], x["tactic"])
        )

        return {
            "framework": "MITRE ATT&CK",
            "unique_techniques": len(techniques_sorted),
            "unique_tactics": len(tactics_sorted),
            "tactics": tactics_sorted,
            "techniques": techniques_sorted,
        }
