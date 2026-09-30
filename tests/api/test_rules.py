"""
API tests for GET /rules.
"""

import json

from cloudsentinel.services.rule_catalog import DEFAULT_RULES_CONFIG


def load_config():
    with open(DEFAULT_RULES_CONFIG, "r", encoding="utf-8") as f:
        return json.load(f)


def test_rules_returns_200(client):
    assert client.get("/rules").status_code == 200


def test_rules_match_rules_config(client):
    config = load_config()
    body = client.get("/rules").json()

    assert body["version"] == config["version"]
    assert body["total"] == len(config["rules"]) == 12
    assert [r["rule_id"] for r in body["rules"]] == [r["rule_id"] for r in config["rules"]]

    for returned, configured in zip(body["rules"], config["rules"]):
        for field in ("rule_id", "rule_name", "severity", "description", "remediation", "mitre_attack"):
            assert returned[field] == configured[field]


def test_rules_consistent_with_scan_findings(client, demo_data):
    """The demo data triggers every rule, so each finding can be checked against the catalog."""
    catalog = {r["rule_id"]: r for r in client.get("/rules").json()["rules"]}
    findings = client.post("/scans", json=demo_data).json()["findings"]

    assert {f["rule_id"] for f in findings} == set(catalog)
    for f in findings:
        assert f["rule_name"] == catalog[f["rule_id"]]["rule_name"]
        assert f["severity"] == catalog[f["rule_id"]]["severity"]
