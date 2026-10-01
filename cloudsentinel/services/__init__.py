"""
CloudSentinel service layer.
Orchestrates the existing scanner package without CLI or file side effects.
Only ExplanationService makes network calls, through an injected LLMProvider.
"""

from .explanation_service import ExplanationService
from .rule_catalog import load_rule_catalog
from .scan_service import ScanService, compute_finding_id, filter_findings, validate_filters

__all__ = [
    "ScanService",
    "ExplanationService",
    "compute_finding_id",
    "filter_findings",
    "validate_filters",
    "load_rule_catalog",
]
