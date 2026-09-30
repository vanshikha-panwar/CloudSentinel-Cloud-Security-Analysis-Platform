"""
API tests for GET /health and POST /scans.

Primary fixture: sample_data/demo_iam_data.json. No AWS or external calls.
"""

import copy
import socket

import pytest

from cloudsentinel.services.scan_service import ScanService

REPORT_SECTIONS = {"scan_metadata", "filters", "summary", "mitre_attack_summary", "findings"}
FINDING_FIELDS = {
    "finding_id", "rule_id", "rule_name", "severity", "affected_entity",
    "entity_type", "description", "remediation", "cvss_score", "mitre_attack",
}


# -----------------------------
# App
# -----------------------------
def test_health(client):
    response = client.get("/health")
    assert response.status_code == 200
    assert response.json() == {"status": "ok"}


def test_external_network_is_blocked():
    with pytest.raises(AssertionError):
        socket.create_connection(("203.0.113.1", 443), timeout=1)


# -----------------------------
# POST /scans: report
# -----------------------------
def test_scan_demo_data_returns_200(client, demo_data):
    assert client.post("/scans", json=demo_data).status_code == 200


def test_scan_response_has_report_sections(client, demo_data):
    body = client.post("/scans", json=demo_data).json()
    assert set(body) == REPORT_SECTIONS
    assert body["summary"] == {"total_findings": 23, "critical": 4, "high": 8, "medium": 7, "low": 4}
    assert body["scan_metadata"]["account_id"] == "123456789012"


def test_findings_have_id_and_existing_fields(client, demo_data):
    findings = client.post("/scans", json=demo_data).json()["findings"]
    assert findings
    ids = [f["finding_id"] for f in findings]
    assert all(i.startswith("fnd_") for i in ids)
    assert len(ids) == len(set(ids))
    for f in findings:
        assert set(f) == FINDING_FIELDS


def test_api_matches_scan_service(client, demo_data):
    expected = ScanService().run_scan(copy.deepcopy(demo_data))
    assert client.post("/scans", json=demo_data).json() == expected


def test_api_matches_scan_service_with_filters(client, demo_data):
    expected = ScanService().run_scan(copy.deepcopy(demo_data), min_severity="MEDIUM", entity_type="USER")
    response = client.post("/scans", params={"min_severity": "MEDIUM", "entity_type": "USER"}, json=demo_data)
    assert response.json() == expected


# -----------------------------
# POST /scans: filters
# -----------------------------
def test_min_severity_filter(client, demo_data):
    body = client.post("/scans", params={"min_severity": "HIGH"}, json=demo_data).json()
    assert {f["severity"] for f in body["findings"]} <= {"CRITICAL", "HIGH"}
    assert body["summary"]["total_findings"] == 12
    assert body["filters"] == {"min_severity": "HIGH", "entity_type": None, "total_findings_before_filter": 23}


def test_entity_type_filter(client, demo_data):
    body = client.post("/scans", params={"entity_type": "ROLE"}, json=demo_data).json()
    assert {f["entity_type"] for f in body["findings"]} == {"ROLE"}
    assert body["summary"]["total_findings"] == 3


def test_filters_are_case_insensitive(client, demo_data):
    lower = client.post("/scans", params={"min_severity": "high", "entity_type": "user"}, json=demo_data)
    upper = client.post("/scans", params={"min_severity": "HIGH", "entity_type": "USER"}, json=demo_data)
    assert lower.status_code == 200
    assert lower.json() == upper.json()


@pytest.mark.parametrize("params", [
    {"min_severity": "SEVERE"},
    {"entity_type": "BUCKET"},
    {"min_severity": "HIGH", "entity_type": "BUCKET"},
])
def test_invalid_filters_return_422(client, demo_data, params):
    response = client.post("/scans", params=params, json=demo_data)
    assert response.status_code == 422
    assert "Invalid" in response.json()["detail"]


# -----------------------------
# POST /scans: request validation
# -----------------------------
@pytest.mark.parametrize("payload", [
    [],                                            # top level must be an object
    "not an object",
    {"users": "alice"},                            # sections must have the right shape
    {"users": ["alice"]},
    {"roles": {"RoleName": "r"}},
    {"password_policy": ["MinimumPasswordLength", 8]},
    {"account_id": {"id": "123456789012"}},
])
def test_invalid_iam_data_returns_422(client, payload):
    assert client.post("/scans", json=payload).status_code == 422


def test_non_json_body_returns_422(client):
    response = client.post("/scans", content=b"{not json", headers={"Content-Type": "application/json"})
    assert response.status_code == 422


def test_missing_body_returns_422(client):
    assert client.post("/scans").status_code == 422


def test_empty_object_is_accepted(client):
    body = client.post("/scans", json={}).json()
    assert body["scan_metadata"]["account_id"] == "UNKNOWN"
    # Missing password policy is treated as weak, as in the CLI
    assert [f["rule_id"] for f in body["findings"]] == ["RULE_009"]


def test_null_sections_and_extra_keys_are_accepted(client, demo_data):
    demo_data["groups"] = None
    demo_data["exported_by"] = "iam-vulnerable"
    response = client.post("/scans", json=demo_data)
    assert response.status_code == 200
    assert response.json()["scan_metadata"]["total_entities_scanned"]["groups"] == 0
