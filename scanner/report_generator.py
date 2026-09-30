"""
Report Generator Module

Produces human-readable terminal reports (with color) and machine-readable JSON reports.
Includes MITRE ATT&CK technique/tactic mapping for each finding and a coverage summary.
"""

import json
import os
from datetime import datetime, timezone
from typing import List, Dict, Any

from .mitre_attack import MitreAttackMapper

try:
    from colorama import Fore, Style, init as colorama_init
    colorama_init(autoreset=True)
    HAS_COLORAMA = True
except ImportError:
    HAS_COLORAMA = False


class ReportGenerator:
    """
    Generates security scan reports in terminal and JSON formats.
    """

    SEVERITY_COLORS = {
        "CRITICAL": "RED",
        "HIGH": "YELLOW",
        "MEDIUM": "CYAN",
        "LOW": "WHITE",
        "INFO": "WHITE"
    }

    def __init__(self, mitre_mapper: MitreAttackMapper = None):
        self.mitre_mapper = mitre_mapper or MitreAttackMapper.from_rules_config()

    def _colorize(self, text: str, severity: str) -> str:
        """Apply color to text based on severity if colorama available."""
        if not HAS_COLORAMA:
            return text

        color = self.SEVERITY_COLORS.get(severity.upper(), "WHITE")
        if color == "RED":
            return f"{Fore.RED}{text}{Style.RESET_ALL}"
        elif color == "YELLOW":
            return f"{Fore.YELLOW}{text}{Style.RESET_ALL}"
        elif color == "CYAN":
            return f"{Fore.CYAN}{text}{Style.RESET_ALL}"
        else:
            return text

    def _format_mitre_line(self, finding: Dict[str, Any]) -> str:
        """Format MITRE ATT&CK info for a single finding."""
        mitre = finding.get("mitre_attack")
        if not mitre:
            rule_id = finding.get("rule_id", "")
            mitre = self.mitre_mapper.get_mapping(rule_id)

        primary = mitre.get("primary_tactic", "Unknown")
        techniques = mitre.get("techniques", [])
        if not techniques:
            return f"MITRE ATT&CK : {primary} | N/A"

        tech_parts = [
            f"{t.get('technique_id')} ({t.get('technique_name')})"
            for t in techniques
        ]
        return f"MITRE ATT&CK : {primary} | " + "; ".join(tech_parts)

    def print_terminal_report(self, findings: List[Dict[str, Any]], scan_metadata: Dict[str, Any]):
        """
        Print formatted report to terminal.
        Findings must be pre-sorted by cvss_score descending.
        """
        account_id = scan_metadata.get('account_id', 'UNKNOWN')
        scan_time = scan_metadata.get('scan_time', datetime.now(timezone.utc).isoformat())

        # Summary counts
        total = len(findings)
        critical = sum(1 for f in findings if f.get('severity') == 'CRITICAL')
        high = sum(1 for f in findings if f.get('severity') == 'HIGH')
        medium = sum(1 for f in findings if f.get('severity') == 'MEDIUM')
        low = sum(1 for f in findings if f.get('severity') == 'LOW')

        mitre_summary = self.mitre_mapper.summarize_findings(findings)

        header = "=" * 60
        print(header)
        print("  AWS IAM SECURITY SCAN REPORT")
        print(f"  Account: {account_id} | {scan_time}")
        print(header)
        print()
        print("SUMMARY")
        print(f"  Total Findings : {total}")
        print(f"  CRITICAL       : {critical}")
        print(f"  HIGH           : {high}")
        print(f"  MEDIUM         : {medium}")
        print(f"  LOW            : {low}")
        print()
        print("MITRE ATT&CK COVERAGE")
        print(f"  Unique Tactics    : {mitre_summary.get('unique_tactics', 0)}")
        print(f"  Unique Techniques : {mitre_summary.get('unique_techniques', 0)}")
        if mitre_summary.get("tactics"):
            print("  Top Tactics:")
            for item in mitre_summary["tactics"][:6]:
                print(f"    - {item['tactic']}: {item['count']} finding(s)")
        if mitre_summary.get("techniques"):
            print("  Top Techniques:")
            for item in mitre_summary["techniques"][:6]:
                print(f"    - {item['technique_id']} {item['technique_name']}: {item['count']}")
        print()
        print("-" * 60)

        if not findings:
            print("No findings to report.")
            print("-" * 60)
            return

        for finding in findings:
            severity = finding.get('severity', 'INFO')
            rule_id = finding.get('rule_id', '')
            rule_name = finding.get('rule_name', '')
            entity = finding.get('affected_entity', '')
            etype = finding.get('entity_type', '')
            score = finding.get('cvss_score', 0.0)
            desc = finding.get('description', '')
            rem = finding.get('remediation', '')

            # Colored severity header
            header_line = f"[{severity}] {rule_id} — {rule_name}"
            print(self._colorize(header_line, severity))
            print(f"Entity       : {entity}")
            print(f"Type         : {etype}")
            print(f"CVSS Score   : {score}")
            print(self._format_mitre_line(finding))
            print(f"Description  : {desc}")
            print(f"Remediation  : {rem}")
            print("-" * 60)

    def save_json_report(self, findings: List[Dict[str, Any]], scan_metadata: Dict[str, Any], output_path: str):
        """
        Write JSON report to disk.
        Creates parent directories if needed.
        Includes MITRE ATT&CK per-finding and coverage summary.
        """
        total = len(findings)
        critical = sum(1 for f in findings if f.get('severity') == 'CRITICAL')
        high = sum(1 for f in findings if f.get('severity') == 'HIGH')
        medium = sum(1 for f in findings if f.get('severity') == 'MEDIUM')
        low = sum(1 for f in findings if f.get('severity') == 'LOW')

        # Ensure findings sorted by cvss_score desc for JSON too
        sorted_findings = sorted(findings, key=lambda x: x.get('cvss_score', 0), reverse=True)

        # Ensure every finding has mitre_attack block
        for finding in sorted_findings:
            if not finding.get("mitre_attack"):
                finding["mitre_attack"] = self.mitre_mapper.get_mapping(finding.get("rule_id", ""))

        mitre_summary = self.mitre_mapper.summarize_findings(sorted_findings)

        report = {
            "scan_metadata": {
                "account_id": scan_metadata.get('account_id', 'UNKNOWN'),
                "scan_time": scan_metadata.get('scan_time', datetime.now(timezone.utc).isoformat()),
                "total_entities_scanned": {
                    "users": scan_metadata.get('total_users', 0),
                    "roles": scan_metadata.get('total_roles', 0),
                    "groups": scan_metadata.get('total_groups', 0)
                },
                "frameworks": ["Custom IAM Rules", "MITRE ATT&CK"]
            },
            "summary": {
                "total_findings": total,
                "critical": critical,
                "high": high,
                "medium": medium,
                "low": low
            },
            "mitre_attack_summary": mitre_summary,
            "findings": sorted_findings
        }

        # Create output directory if it does not exist
        os.makedirs(os.path.dirname(output_path) or '.', exist_ok=True)

        with open(output_path, 'w', encoding='utf-8') as f:
            json.dump(report, f, indent=2, default=str)

        return output_path
