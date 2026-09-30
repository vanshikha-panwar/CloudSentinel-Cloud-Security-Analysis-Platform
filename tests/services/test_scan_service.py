"""
Unit tests for the CloudSentinel scan service.

Primary fixture: sample_data/demo_iam_data.json. No real AWS calls are made.
"""

import copy
import json
import os
import sys
from datetime import datetime, timezone
from pathlib import Path

import pytest

from cloudsentinel.services.scan_service import (
    ScanService,
    compute_finding_id,
    filter_findings,
)
from scanner.rule_engine import RuleEngine

DEMO_DATA_PATH = Path(__file__).resolve().parents[2] / "sample_data" / "demo_iam_data.json"

EXISTING_FINDING_FIELDS = {
    "rule_id", "rule_name", "severity", "affected_entity", "entity_type",
    "description", "remediation", "cvss_score", "mitre_attack",
}


@pytest.fixture
def demo_data():
    with open(DEMO_DATA_PATH, "r", encoding="utf-8") as f:
        return json.load(f)


@pytest.fixture(scope="module")
def service():
    return ScanService()


def finding_key(f):
    return (f["rule_id"], f["affected_entity"], f["description"])


# -----------------------------
# Report structure
# -----------------------------
def test_report_has_expected_top_level_keys(service, demo_data):
    report = service.run_scan(demo_data)
    assert set(report) == {"scan_metadata", "filters", "summary", "mitre_attack_summary", "findings"}


def test_scan_metadata_from_demo_data(service, demo_data):
    meta = service.run_scan(demo_data)["scan_metadata"]
    assert meta["account_id"] == "123456789012"
    assert meta["scan_time"] == "2026-07-28T10:00:00+00:00"
    assert meta["total_entities_scanned"] == {"users": 4, "roles": 3, "groups": 1}
    assert meta["frameworks"] == ["Custom IAM Rules", "MITRE ATT&CK"]


def test_summary_counts_for_demo_data(service, demo_data):
    summary = service.run_scan(demo_data)["summary"]
    assert summary == {"total_findings": 23, "critical": 4, "high": 8, "medium": 7, "low": 4}


def test_report_is_json_serializable(service, demo_data):
    json.dumps(service.run_scan(demo_data))


def test_datetime_scan_time_is_serialized(service, demo_data):
    demo_data["scan_time"] = datetime(2026, 7, 28, 10, 0, tzinfo=timezone.utc)
    report = service.run_scan(demo_data)
    assert report["scan_metadata"]["scan_time"] == "2026-07-28T10:00:00+00:00"


def test_empty_iam_data_uses_defaults(service):
    report = service.run_scan({})
    assert report["scan_metadata"]["account_id"] == "UNKNOWN"
    assert report["scan_metadata"]["scan_time"]
    # Empty password policy is weak -> RULE_009 only
    assert [f["rule_id"] for f in report["findings"]] == ["RULE_009"]


# -----------------------------
# Findings: parity with the existing engine
# -----------------------------
def test_findings_match_rule_engine_output(service, demo_data):
    engine_findings = RuleEngine().run_all_rules(copy.deepcopy(demo_data))
    report_findings = service.run_scan(demo_data)["findings"]

    assert sorted(map(finding_key, report_findings)) == sorted(map(finding_key, engine_findings))

    by_key = {finding_key(f): f for f in engine_findings}
    for f in report_findings:
        original = by_key[finding_key(f)]
        assert {k: v for k, v in f.items() if k != "finding_id"} == original


def test_findings_preserve_existing_fields(service, demo_data):
    for f in service.run_scan(demo_data)["findings"]:
        assert EXISTING_FINDING_FIELDS.issubset(f.keys())
        assert set(f.keys()) == EXISTING_FINDING_FIELDS | {"finding_id"}


def test_findings_sorted_by_cvss_desc(service, demo_data):
    scores = [f["cvss_score"] for f in service.run_scan(demo_data)["findings"]]
    assert scores == sorted(scores, reverse=True)


def test_input_data_is_not_mutated(service, demo_data):
    before = copy.deepcopy(demo_data)
    service.run_scan(demo_data)
    assert demo_data == before


# -----------------------------
# finding_id
# -----------------------------
def test_every_finding_has_unique_prefixed_id(service, demo_data):
    ids = [f["finding_id"] for f in service.run_scan(demo_data)["findings"]]
    assert all(i.startswith("fnd_") for i in ids)
    assert len(ids) == len(set(ids))


def test_finding_ids_are_deterministic(demo_data):
    first = {finding_key(f): f["finding_id"] for f in ScanService().run_scan(copy.deepcopy(demo_data))["findings"]}
    second = {finding_key(f): f["finding_id"] for f in ScanService().run_scan(copy.deepcopy(demo_data))["findings"]}
    assert first == second


def test_finding_id_stable_when_day_counts_change(service, demo_data):
    def stale_key_ids(data):
        return sorted(
            f["finding_id"] for f in service.run_scan(data)["findings"]
            if f["rule_id"] in ("RULE_004", "RULE_005")
        )

    before = stale_key_ids(copy.deepcopy(demo_data))
    for key in demo_data["users"][0]["access_keys"]:
        key["DaysSinceLastUsed"] += 60
        key["AgeDays"] += 60
    assert stale_key_ids(demo_data) == before


def test_finding_id_differs_across_accounts(service, demo_data):
    other = copy.deepcopy(demo_data)
    other["account_id"] = "999999999999"

    def rule_009_id(data):
        return [f for f in service.run_scan(data)["findings"] if f["rule_id"] == "RULE_009"][0]["finding_id"]

    assert rule_009_id(demo_data) != rule_009_id(other)


def test_finding_ids_do_not_depend_on_filters(service, demo_data):
    all_ids = {finding_key(f): f["finding_id"] for f in service.run_scan(demo_data)["findings"]}
    for f in service.run_scan(demo_data, min_severity="HIGH", entity_type="ROLE")["findings"]:
        assert all_ids[finding_key(f)] == f["finding_id"]


def test_colliding_findings_get_unique_ids(service, demo_data):
    # Duplicate user entry produces identical findings; IDs must still be unique
    demo_data["users"].append(copy.deepcopy(demo_data["users"][0]))
    ids = [f["finding_id"] for f in service.run_scan(demo_data)["findings"]]
    assert len(ids) == len(set(ids))
    assert any(i.endswith("-2") for i in ids)


def test_compute_finding_id_ignores_numbers_only():
    base = {"rule_id": "RULE_004", "entity_type": "USER", "affected_entity": "arn:x", "description": "unused 240 days"}
    later = dict(base, description="unused 300 days")
    other = dict(base, description="different text")
    assert compute_finding_id(base, "1") == compute_finding_id(later, "1")
    assert compute_finding_id(base, "1") != compute_finding_id(other, "1")


# -----------------------------
# Filtering
# -----------------------------
def test_min_severity_filter(service, demo_data):
    report = service.run_scan(demo_data, min_severity="HIGH")
    severities = {f["severity"] for f in report["findings"]}
    assert severities <= {"CRITICAL", "HIGH"}
    assert report["summary"]["total_findings"] == 12
    assert report["filters"] == {"min_severity": "HIGH", "entity_type": None, "total_findings_before_filter": 23}


def test_entity_type_filter(service, demo_data):
    report = service.run_scan(demo_data, entity_type="ROLE")
    assert {f["entity_type"] for f in report["findings"]} == {"ROLE"}
    assert report["summary"]["total_findings"] == 3


def test_combined_filters(service, demo_data):
    report = service.run_scan(demo_data, min_severity="CRITICAL", entity_type="ACCOUNT")
    assert [f["rule_id"] for f in report["findings"]] == ["RULE_001"]


def test_filters_are_case_insensitive(service, demo_data):
    lower = service.run_scan(demo_data, min_severity="high", entity_type="user")
    upper = service.run_scan(demo_data, min_severity="HIGH", entity_type="USER")
    assert lower == upper


@pytest.mark.parametrize("kwargs", [{"min_severity": "SEVERE"}, {"entity_type": "BUCKET"}])
def test_invalid_filters_raise(service, demo_data, kwargs):
    with pytest.raises(ValueError):
        service.run_scan(demo_data, **kwargs)


@pytest.mark.parametrize("severity", [None, "CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"])
@pytest.mark.parametrize("entity_type", [None, "USER", "ROLE", "GROUP", "ACCOUNT"])
def test_filter_parity_with_cli(demo_data, severity, entity_type):
    import main as cli  # parity check only; the service itself never imports main

    findings = RuleEngine().run_all_rules(demo_data)
    assert filter_findings(findings, severity, entity_type) == cli.filter_findings(findings, severity, entity_type)


def test_non_dict_input_raises(service):
    with pytest.raises(TypeError):
        service.run_scan([])


# -----------------------------
# MITRE ATT&CK
# -----------------------------
def test_every_finding_has_mitre_mapping(service, demo_data):
    for f in service.run_scan(demo_data)["findings"]:
        assert f["mitre_attack"]["framework"] == "MITRE ATT&CK"
        assert f["mitre_attack"]["techniques"]


def test_mitre_summary_matches_existing_mapper(service, demo_data):
    report = service.run_scan(demo_data)
    assert report["mitre_attack_summary"] == service.mitre_mapper.summarize_findings(report["findings"])
    assert report["mitre_attack_summary"]["unique_techniques"] >= 1


# -----------------------------
# Side effects
# -----------------------------
def test_no_stdout_output(service, demo_data, capsys):
    service.run_scan(demo_data)
    captured = capsys.readouterr()
    assert captured.out == ""


def test_no_files_written(service, demo_data, tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    service.run_scan(demo_data)
    assert os.listdir(tmp_path) == []


def test_no_aws_calls(demo_data, monkeypatch):
    def fail(*args, **kwargs):
        raise AssertionError("scan_service must not create AWS sessions or clients")

    boto3 = sys.modules.get("boto3")
    if boto3 is not None:
        # Already imported elsewhere: block session/client creation
        monkeypatch.setattr(boto3, "Session", fail)
        monkeypatch.setattr(boto3, "client", fail)
    else:
        # Not imported: make any import attempt fail
        monkeypatch.setitem(sys.modules, "boto3", None)
        monkeypatch.setitem(sys.modules, "botocore", None)

    ScanService().run_scan(demo_data)
