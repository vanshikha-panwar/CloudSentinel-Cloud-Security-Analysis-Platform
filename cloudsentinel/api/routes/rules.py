"""
Rule catalog routes.
"""

from typing import Any, Dict

from fastapi import APIRouter

from cloudsentinel.api.schemas import RulesResponse
from cloudsentinel.services.rule_catalog import load_rule_catalog

router = APIRouter(tags=["rules"])


@router.get("/rules", response_model=RulesResponse)
def list_rules() -> Dict[str, Any]:
    """List the scanner's security rules from rules/rules_config.json."""
    return load_rule_catalog()
