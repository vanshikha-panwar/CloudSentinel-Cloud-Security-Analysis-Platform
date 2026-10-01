"""
Unit tests for the SQLite persistence layer (cloudsentinel.db).

Every test uses a temporary database file; reports and explanations come
from the real ScanService / ExplanationService on the demo dataset.
"""

import copy
import json
import re
import sqlite3
from pathlib import Path

import pytest

from cloudsentinel.db import ENV_DB_PATH, PersistenceError, ScanRepository, get_db_path
from cloudsentinel.db.database import DEFAULT_DB_PATH, SCHEMA_VERSION, connect, init_db
from cloudsentinel.llm import LLMProvider
from cloudsentinel.services.explanation_service import ExplanationService
from cloudsentinel.services.scan_service import ScanService

DEMO_DATA_PATH = Path(__file__).resolve().parents[2] / "sample_data" / "demo_iam_data.json"
SECRET = "sk-test-SECRET-never-stored"

EXPLANATION = {
    "summary": "The root account has no MFA.",
    "why_it_matters": "Root has unrestricted access.",
    "attack_scenario": "A stolen root password gives full control.",
    "remediation_explained": "Enabling MFA adds a second factor.",
}


class FakeProvider(LLMProvider):
    name = "fake"
    model = "fake-model"

    def __init__(self):
        self._api_key = SECRET   # mimic a real provider holding a secret

    def generate_json(self, system_prompt, user_prompt):
        return json.dumps(EXPLANATION)


@pytest.fixture
def demo_data():
    with open(DEMO_DATA_PATH, "r", encoding="utf-8") as f:
        return json.load(f)


@pytest.fixture
def report(demo_data):
    return ScanService().run_scan(demo_data)


@pytest.fixture
def repo(tmp_path):
    return ScanRepository(tmp_path / "nested" / "dir" / "history.db")


def table_names(db_path):
    with sqlite3.connect(db_path) as conn:
        return {row[0] for row in conn.execute("SELECT name FROM sqlite_master WHERE type = 'table'")}


def db_bytes(db_path):
    return b"".join(p.read_bytes() for p in Path(db_path).parent.glob(Path(db_path).name + "*"))


# -----------------------------
# Configuration and initialization
# -----------------------------
def test_default_db_path():
    assert get_db_path({}) == DEFAULT_DB_PATH
    assert DEFAULT_DB_PATH.name == "cloudsentinel.db"
    assert DEFAULT_DB_PATH.parent.name == "data"


def test_db_path_from_environment(tmp_path):
    assert get_db_path({ENV_DB_PATH: str(tmp_path / "custom.db")}) == tmp_path / "custom.db"


def test_blank_db_path_uses_default():
    assert get_db_path({ENV_DB_PATH: "   "}) == DEFAULT_DB_PATH


def test_db_path_reads_process_environment(monkeypatch, tmp_path):
    monkeypatch.setenv(ENV_DB_PATH, str(tmp_path / "env.db"))
    assert get_db_path() == tmp_path / "env.db"


def test_database_not_created_until_first_use(repo):
    assert not repo.db_path.exists()


def test_first_use_creates_file_directories_and_schema(repo):
    assert repo.list_scans() == []
    assert repo.db_path.exists()
    assert {"scans", "findings", "explanations"} <= table_names(repo.db_path)
    with sqlite3.connect(repo.db_path) as conn:
        assert conn.execute("PRAGMA user_version").fetchone()[0] == SCHEMA_VERSION


def test_init_is_idempotent(tmp_path, report):
    db_path = tmp_path / "history.db"
    ScanRepository(db_path).save_scan(report)
    # A new repository on the same file re-runs init without losing data
    second = ScanRepository(db_path)
    assert len(second.list_scans()) == 1
    conn = connect(db_path)
    try:
        init_db(conn)
        init_db(conn)
    finally:
        conn.close()
    assert len(second.list_scans()) == 1


def test_newer_schema_version_rejected(tmp_path):
    db_path = tmp_path / "future.db"
    with sqlite3.connect(db_path) as conn:
        conn.execute(f"PRAGMA user_version = {SCHEMA_VERSION + 1}")
    with pytest.raises(PersistenceError):
        ScanRepository(db_path).list_scans()


def test_unusable_path_raises_persistence_error(tmp_path):
    # The path is an existing directory, so SQLite cannot open it as a file
    with pytest.raises(PersistenceError):
        ScanRepository(tmp_path).save_scan({"scan_metadata": {}, "filters": {}, "summary": {}, "findings": []})


# -----------------------------
# Scans and findings
# -----------------------------
def test_save_scan_returns_scan_id(repo, report):
    scan_id = repo.save_scan(report)
    assert re.fullmatch(r"scn_[0-9a-f]{32}", scan_id)


def test_scan_round_trip_matches_report(repo, report):
    original = copy.deepcopy(report)
    scan_id = repo.save_scan(report)
    stored = repo.get_scan(scan_id)

    assert stored["scan_id"] == scan_id
    assert stored["created_at"]
    assert {k: v for k, v in stored.items() if k not in ("scan_id", "created_at")} == original
    assert report == original   # input not mutated


def test_findings_stored_in_report_order(repo, report):
    stored = repo.get_scan(repo.save_scan(report))
    assert [f["finding_id"] for f in stored["findings"]] == [f["finding_id"] for f in report["findings"]]


def test_finding_rows_match_scanner_findings(repo, report):
    scan_id = repo.save_scan(report)
    with sqlite3.connect(repo.db_path) as conn:
        rows = conn.execute(
            "SELECT position, finding_id, rule_id, rule_name, severity, cvss_score, entity_type, affected_entity, "
            "finding_json FROM findings WHERE scan_id = ? ORDER BY position",
            (scan_id,),
        ).fetchall()

    assert len(rows) == len(report["findings"]) == 23
    for row, finding in zip(rows, report["findings"]):
        position, finding_id, rule_id, rule_name, severity, cvss, entity_type, entity, finding_json = row
        assert (finding_id, rule_id, rule_name, severity, cvss, entity_type, entity) == (
            finding["finding_id"], finding["rule_id"], finding["rule_name"], finding["severity"],
            finding["cvss_score"], finding["entity_type"], finding["affected_entity"],
        )
        assert json.loads(finding_json) == finding


def test_scan_metadata_columns(repo, report):
    scan_id = repo.save_scan(report)
    with sqlite3.connect(repo.db_path) as conn:
        account_id, scan_time, total, critical = conn.execute(
            "SELECT account_id, scan_time, total_findings, critical FROM scans WHERE scan_id = ?", (scan_id,)
        ).fetchone()
    assert (account_id, scan_time, total, critical) == ("123456789012", "2026-07-28T10:00:00+00:00", 23, 4)


def test_filtered_report_stored_as_returned(repo, demo_data):
    filtered = ScanService().run_scan(demo_data, min_severity="HIGH", entity_type="USER")
    stored = repo.get_scan(repo.save_scan(filtered))
    assert stored["filters"] == {"min_severity": "HIGH", "entity_type": "USER", "total_findings_before_filter": 23}
    assert stored["findings"] == filtered["findings"]


def test_empty_report_round_trip(repo):
    report = ScanService().run_scan({"account_id": "111111111111", "password_policy": {
        "MinimumPasswordLength": 14, "RequireSymbols": True, "RequireNumbers": True,
        "RequireUppercaseCharacters": True, "MaxPasswordAge": 90, "PasswordReusePrevention": 5,
    }})
    assert report["findings"] == []
    stored = repo.get_scan(repo.save_scan(report))
    assert stored["findings"] == []
    assert stored["summary"]["total_findings"] == 0


def test_same_findings_in_two_scans(repo, report):
    first = repo.save_scan(report)
    second = repo.save_scan(report)
    assert first != second
    assert repo.get_scan(first)["findings"] == repo.get_scan(second)["findings"]


def test_get_unknown_scan_returns_none(repo):
    assert repo.get_scan("scn_" + "0" * 32) is None


def test_list_scans_newest_first_with_pagination(repo, report):
    ids = [repo.save_scan(report) for _ in range(3)]
    listed = repo.list_scans()
    assert [s["scan_id"] for s in listed] == list(reversed(ids))
    assert listed[0]["summary"] == report["summary"]
    assert listed[0]["filters"] == report["filters"]
    assert listed[0]["account_id"] == "123456789012"

    assert [s["scan_id"] for s in repo.list_scans(limit=1)] == [ids[2]]
    assert [s["scan_id"] for s in repo.list_scans(limit=2, offset=1)] == [ids[1], ids[0]]


def test_failed_save_is_rolled_back(repo, report):
    broken = copy.deepcopy(report)
    broken["findings"].append(copy.deepcopy(broken["findings"][0]))   # duplicate (scan_id, finding_id)
    with pytest.raises(PersistenceError):
        repo.save_scan(broken)
    assert repo.list_scans() == []
    with sqlite3.connect(repo.db_path) as conn:
        assert conn.execute("SELECT COUNT(*) FROM findings").fetchone()[0] == 0


# -----------------------------
# Parameterized SQL
# -----------------------------
def test_sql_injection_strings_are_treated_as_data(repo, report):
    hostile = "x' OR '1'='1'; DROP TABLE scans; --"
    report = copy.deepcopy(report)
    report["scan_metadata"]["account_id"] = hostile
    report["findings"][0]["description"] = hostile

    scan_id = repo.save_scan(report)
    stored = repo.get_scan(scan_id)
    assert stored["scan_metadata"]["account_id"] == hostile
    assert stored["findings"][0]["description"] == hostile
    assert repo.get_scan(hostile) is None
    assert repo.list_explanations(hostile) == []
    assert {"scans", "findings", "explanations"} <= table_names(repo.db_path)


# -----------------------------
# AI explanations
# -----------------------------
def explain(report, rule_id="RULE_001"):
    finding = next(f for f in report["findings"] if f["rule_id"] == rule_id)
    return ExplanationService(FakeProvider()).explain(finding)


def test_save_and_list_explanation(repo, report):
    result = explain(report)
    explanation_id = repo.save_explanation(result)
    stored = repo.list_explanations(result["finding_id"])

    assert len(stored) == 1
    entry = stored[0]
    assert entry["explanation_id"] == explanation_id
    assert entry["created_at"]
    assert {k: v for k, v in entry.items() if k not in ("explanation_id", "created_at")} == result


def test_explanation_columns_keep_scanner_fields(repo, report):
    result = explain(report)
    repo.save_explanation(result)
    with sqlite3.connect(repo.db_path) as conn:
        rule_id, severity, cvss, provider, model = conn.execute(
            "SELECT rule_id, severity, cvss_score, provider, model FROM explanations"
        ).fetchone()
    assert (rule_id, severity, cvss) == ("RULE_001", "CRITICAL", 10.0)
    assert (provider, model) == ("fake", "fake-model")


def test_explanations_newest_first_and_per_finding(repo, report):
    first = repo.save_explanation(explain(report))
    second = repo.save_explanation(explain(report))
    other = explain(report, "RULE_009")
    repo.save_explanation(other)

    rule_001_id = explain(report)["finding_id"]
    assert [e["explanation_id"] for e in repo.list_explanations(rule_001_id)] == [second, first]
    assert len(repo.list_explanations(other["finding_id"])) == 1
    assert repo.list_explanations("fnd_" + "0" * 16) == []


def test_no_secrets_or_raw_iam_data_stored(repo, report):
    repo.save_scan(report)
    repo.save_explanation(explain(report))
    data = db_bytes(repo.db_path)
    assert SECRET.encode() not in data
    # Raw IAM input (policy documents, trust policies) is never stored
    for raw in (b"PolicyDocument", b"AssumeRolePolicyDocument", b"\"Statement\""):
        assert raw not in data
