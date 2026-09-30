"""
Rule Catalog Module

Exposes the scanner's rule definitions from rules/rules_config.json,
the same file MitreAttackMapper.from_rules_config() reads. No rule
definitions are duplicated here.
"""

import json
from pathlib import Path
from typing import Any, Dict, Optional, Union

import scanner

# Resolved the same way as MitreAttackMapper.from_rules_config()
DEFAULT_RULES_CONFIG = Path(scanner.__file__).resolve().parent.parent / "rules" / "rules_config.json"

RULE_FIELDS = ("rule_id", "rule_name", "severity", "description", "remediation", "mitre_attack")


def load_rule_catalog(config_path: Optional[Union[str, Path]] = None) -> Dict[str, Any]:
    """
    Load the rule catalog from the rules config file.

    Returns:
        {"version": str | None, "total": int, "rules": [ {RULE_FIELDS...}, ... ]}

    Raises:
        FileNotFoundError: config file is missing.
        ValueError: config file is not valid JSON.
    """
    path = Path(config_path) if config_path else DEFAULT_RULES_CONFIG
    with open(path, "r", encoding="utf-8") as f:
        config = json.load(f)

    rules = [{field: rule.get(field) for field in RULE_FIELDS} for rule in config.get("rules", [])]
    return {"version": config.get("version"), "total": len(rules), "rules": rules}
