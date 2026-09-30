"""
Pydantic models for the CloudSentinel API.

The IAM request model validates only the top-level structure. Entity
contents (users, roles, groups, policies) pass through as plain dicts so
the scanner remains the single owner of the IAM data format.
"""

from typing import Any, Dict, List, Optional

from pydantic import BaseModel, ConfigDict


class IamDataRequest(BaseModel):
    """IAM data in the same format as the CLI's --input-file JSON."""

    # Exported files may carry extra keys; keep them rather than rejecting
    model_config = ConfigDict(extra="allow")

    account_id: Optional[str] = None
    scan_time: Optional[str] = None
    users: Optional[List[Dict[str, Any]]] = None
    groups: Optional[List[Dict[str, Any]]] = None
    roles: Optional[List[Dict[str, Any]]] = None
    password_policy: Optional[Dict[str, Any]] = None
    account_summary: Optional[Dict[str, Any]] = None


class Finding(BaseModel):
    """A single finding. Extra fields added by the scanner are passed through."""

    model_config = ConfigDict(extra="allow")

    finding_id: str
    rule_id: str
    rule_name: str
    severity: str
    affected_entity: str
    entity_type: str
    description: str
    remediation: str
    cvss_score: float
    mitre_attack: Dict[str, Any]


class ScanFilters(BaseModel):
    min_severity: Optional[str]
    entity_type: Optional[str]
    total_findings_before_filter: int


class SeveritySummary(BaseModel):
    total_findings: int
    critical: int
    high: int
    medium: int
    low: int


class ScanReport(BaseModel):
    """Report returned by ScanService.run_scan()."""

    model_config = ConfigDict(extra="allow")

    scan_metadata: Dict[str, Any]
    filters: ScanFilters
    summary: SeveritySummary
    mitre_attack_summary: Dict[str, Any]
    findings: List[Finding]


class Rule(BaseModel):
    rule_id: str
    rule_name: str
    severity: str
    description: Optional[str] = None
    remediation: Optional[str] = None
    mitre_attack: Optional[Dict[str, Any]] = None


class RulesResponse(BaseModel):
    version: Optional[str] = None
    total: int
    rules: List[Rule]


class HealthResponse(BaseModel):
    status: str
