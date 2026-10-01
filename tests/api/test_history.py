"""
API tests for scan and explanation persistence.

Uses the per-test temporary database from conftest.py (isolate_database).
The LLM provider is always a fake or a mocked HTTP transport.
"""

import json
import re
import sqlite3
from pathlib import Path

import httpx
import pytest

from cloudsentinel.api.routes.findings import get_explanation_service
from cloudsentinel.api.routes.scans import get_scan_repository
from cloudsentinel.db import ENV_DB_PATH
from cloudsentinel.llm import LLMProvider, LLMTimeoutError, OpenAICompatibleProvider
from cloudsentinel.services.explanation_service import ExplanationService
from cloudsentinel.services.scan_service import ScanService

SCAN_ID = re.compile(r"scn_[0-9a-f]{32}")
UNKNOWN_SCAN_ID = "scn_" + "0" * 32
SECRET = "sk-live-SECRET-must-not-be-stored"
EXPLANATION = {
    "summary": "Summary text.",
    "why_it_matters": "Why it matters text.",
    "attack_scenario": "Attack scenario text.",
    "remediation_explained": "Remediation explanation text.",
}


class FakeProvider(LLMProvider):
    name = "fake"
    model = "fake-model"

    def __init__(self, error=None):
        self.error = error

    def generate_json(self, system_prompt, user_prompt):
        if self.error:
            raise self.error
        return json.dumps(EXPLANATION)


def use_provider(client, provider):
    client.app.dependency_overrides[get_explanation_service] = lambda: ExplanationService(provider)


def post_scan(client, demo_data, **params):
    return client.post("/scans", params=params, json=demo_data)


def first_finding_id(client, demo_data):
    return post_scan(client, demo_data).json()["findings"][0]["finding_id"]


def db_bytes(db_path):
    return b"".join(p.read_bytes() for p in Path(db_path).parent.glob(Path(db_path).name + "*"))


# -----------------------------
# POST /scans persistence
# -----------------------------
def test_scan_returns_scan_id_header(client, demo_data):
    response = post_scan(client, demo_data)
    assert response.status_code == 200
    assert SCAN_ID.fullmatch(response.headers["X-Scan-Id"])


def test_scan_body_unchanged_by_persistence(client, demo_data):
    response = post_scan(client, demo_data)
    assert response.json() == ScanService().run_scan(json.loads(json.dumps(demo_data)))
    assert "scan_id" not in response.json()


def test_database_created_automatically(client, demo_data, isolate_database):
    assert not isolate_database.exists()
    post_scan(client, demo_data)
    assert isolate_database.exists()


def test_scan_and_findings_written_to_database(client, demo_data, isolate_database):
    response = post_scan(client, demo_data)
    scan_id = response.headers["X-Scan-Id"]
    with sqlite3.connect(isolate_database) as conn:
        assert conn.execute("SELECT COUNT(*) FROM scans WHERE scan_id = ?", (scan_id,)).fetchone()[0] == 1
        stored_ids = [r[0] for r in conn.execute(
            "SELECT finding_id FROM findings WHERE scan_id = ? ORDER BY position", (scan_id,))]
    assert stored_ids == [f["finding_id"] for f in response.json()["findings"]]


def test_invalid_scan_request_is_not_stored(client, demo_data, isolate_database):
    assert post_scan(client, demo_data, min_severity="SEVERE").status_code == 422
    assert client.post("/scans", json={"users": "alice"}).status_code == 422
    assert client.get("/scans").json()["scans"] == []


# -----------------------------
# GET /scans/{scan_id}
# -----------------------------
def test_get_stored_scan_matches_original_response(client, demo_data):
    response = post_scan(client, demo_data)
    stored = client.get(f"/scans/{response.headers['X-Scan-Id']}")
    assert stored.status_code == 200
    body = stored.json()
    assert body["scan_id"] == response.headers["X-Scan-Id"]
    assert body["created_at"]
    assert {k: v for k, v in body.items() if k not in ("scan_id", "created_at")} == response.json()


def test_get_stored_filtered_scan(client, demo_data):
    response = post_scan(client, demo_data, min_severity="HIGH", entity_type="ROLE")
    body = client.get(f"/scans/{response.headers['X-Scan-Id']}").json()
    assert body["filters"] == {"min_severity": "HIGH", "entity_type": "ROLE", "total_findings_before_filter": 23}
    assert body["findings"] == response.json()["findings"]


def test_get_unknown_scan_returns_404(client):
    assert client.get(f"/scans/{UNKNOWN_SCAN_ID}").status_code == 404


@pytest.mark.parametrize("scan_id", ["abc", "scn_123", "scn_" + "G" * 32, "SCN_" + "0" * 32, "x' OR '1'='1"])
def test_malformed_scan_id_returns_422(client, scan_id):
    assert client.get(f"/scans/{scan_id}").status_code == 422


# -----------------------------
# GET /scans
# -----------------------------
def test_list_scans_newest_first(client, demo_data):
    ids = [post_scan(client, demo_data).headers["X-Scan-Id"] for _ in range(3)]
    body = client.get("/scans").json()
    assert body["limit"] == 20
    assert body["offset"] == 0
    assert [s["scan_id"] for s in body["scans"]] == list(reversed(ids))
    assert body["scans"][0]["summary"] == {"total_findings": 23, "critical": 4, "high": 8, "medium": 7, "low": 4}
    assert body["scans"][0]["account_id"] == "123456789012"


def test_list_scans_pagination(client, demo_data):
    ids = [post_scan(client, demo_data).headers["X-Scan-Id"] for _ in range(3)]
    body = client.get("/scans", params={"limit": 1, "offset": 1}).json()
    assert [s["scan_id"] for s in body["scans"]] == [ids[1]]


def test_list_scans_empty(client):
    assert client.get("/scans").json() == {"limit": 20, "offset": 0, "scans": []}


@pytest.mark.parametrize("params", [{"limit": 0}, {"limit": 101}, {"offset": -1}, {"limit": "x"}])
def test_list_scans_invalid_params_return_422(client, params):
    assert client.get("/scans", params=params).status_code == 422


# -----------------------------
# Explanation persistence
# -----------------------------
def test_successful_explanation_is_stored(client, demo_data):
    use_provider(client, FakeProvider())
    finding_id = first_finding_id(client, demo_data)

    response = client.post(f"/findings/{finding_id}/explain", json=demo_data)
    assert response.status_code == 200
    explanation_id = int(response.headers["X-Explanation-Id"])

    history = client.get(f"/findings/{finding_id}/explanations")
    assert history.status_code == 200
    body = history.json()
    assert body["finding_id"] == finding_id
    assert body["total"] == 1
    stored = body["explanations"][0]
    assert stored["explanation_id"] == explanation_id
    assert {k: v for k, v in stored.items() if k not in ("explanation_id", "created_at")} == response.json()


def test_explanation_body_unchanged_by_persistence(client, demo_data):
    use_provider(client, FakeProvider())
    finding_id = first_finding_id(client, demo_data)
    body = client.post(f"/findings/{finding_id}/explain", json=demo_data).json()
    assert set(body) == {"finding_id", "finding", "explanation", "ai"}


def test_explanation_history_newest_first(client, demo_data):
    use_provider(client, FakeProvider())
    finding_id = first_finding_id(client, demo_data)
    ids = [int(client.post(f"/findings/{finding_id}/explain", json=demo_data).headers["X-Explanation-Id"])
           for _ in range(2)]
    body = client.get(f"/findings/{finding_id}/explanations").json()
    assert [e["explanation_id"] for e in body["explanations"]] == list(reversed(ids))


def test_no_explanations_returns_empty_list(client):
    body = client.get("/findings/fnd_0000000000000000/explanations").json()
    assert body == {"finding_id": "fnd_0000000000000000", "total": 0, "explanations": []}


@pytest.mark.parametrize("finding_id", ["abc", "fnd_123", "fnd_0123456789ABCDEF"])
def test_malformed_finding_id_in_history_returns_422(client, finding_id):
    assert client.get(f"/findings/{finding_id}/explanations").status_code == 422


def test_failed_explanation_is_not_stored(client, demo_data):
    use_provider(client, FakeProvider(error=LLMTimeoutError("slow")))
    finding_id = first_finding_id(client, demo_data)
    response = client.post(f"/findings/{finding_id}/explain", json=demo_data)
    assert response.status_code == 504
    assert "X-Explanation-Id" not in response.headers
    assert client.get(f"/findings/{finding_id}/explanations").json()["total"] == 0


def test_disabled_ai_stores_nothing(client, demo_data):
    finding_id = first_finding_id(client, demo_data)
    assert client.post(f"/findings/{finding_id}/explain", json=demo_data).status_code == 503
    assert client.get(f"/findings/{finding_id}/explanations").json()["total"] == 0


def test_api_key_never_stored(client, demo_data, isolate_database):
    def handler(request):
        return httpx.Response(200, json={"choices": [{"message": {"content": json.dumps(EXPLANATION)}}]})

    provider = OpenAICompatibleProvider("https://llm.example.test/v1", "test-model", SECRET,
                                        transport=httpx.MockTransport(handler))
    use_provider(client, provider)
    finding_id = first_finding_id(client, demo_data)
    assert client.post(f"/findings/{finding_id}/explain", json=demo_data).status_code == 200

    data = db_bytes(isolate_database)
    assert b"test-model" in data          # sanity: the explanation was written
    assert SECRET.encode() not in data


# -----------------------------
# Database unavailable: scanning keeps working
# -----------------------------
@pytest.fixture
def broken_database(monkeypatch, tmp_path):
    # A directory cannot be opened as a SQLite file
    monkeypatch.setenv(ENV_DB_PATH, str(tmp_path))
    get_scan_repository.cache_clear()


def test_scan_still_returned_when_database_unavailable(client, demo_data, broken_database):
    response = post_scan(client, demo_data)
    assert response.status_code == 200
    assert "X-Scan-Id" not in response.headers
    assert response.json()["summary"]["total_findings"] == 23


def test_explanation_still_returned_when_database_unavailable(client, demo_data, broken_database):
    use_provider(client, FakeProvider())
    finding_id = first_finding_id(client, demo_data)
    response = client.post(f"/findings/{finding_id}/explain", json=demo_data)
    assert response.status_code == 200
    assert "X-Explanation-Id" not in response.headers
    assert response.json()["explanation"] == EXPLANATION


@pytest.mark.parametrize("path", ["/scans", f"/scans/{UNKNOWN_SCAN_ID}", "/findings/fnd_0000000000000000/explanations"])
def test_history_endpoints_return_503_when_database_unavailable(client, broken_database, path):
    response = client.get(path)
    assert response.status_code == 503
    assert response.json() == {"detail": "Scan history is unavailable"}
