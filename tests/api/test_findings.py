"""
API tests for POST /findings/{finding_id}/explain.

The LLM provider is replaced through FastAPI dependency overrides (fake
provider or httpx.MockTransport). No test makes a real LLM call.
"""

import json

import httpx
import pytest

from cloudsentinel.api.routes.findings import get_explanation_service
from cloudsentinel.llm import (
    LLMInvalidResponseError,
    LLMNotConfiguredError,
    LLMProvider,
    LLMProviderError,
    LLMTimeoutError,
    LLMUnavailableError,
    OpenAICompatibleProvider,
)
from cloudsentinel.services.explanation_service import DISCLAIMER, ExplanationService

VALID_EXPLANATION = {
    "summary": "Summary text.",
    "why_it_matters": "Why it matters text.",
    "attack_scenario": "Attack scenario text.",
    "remediation_explained": "Remediation explanation text.",
}
UNKNOWN_ID = "fnd_0000000000000000"
SECRET = "sk-live-SECRET-should-never-leak"


class FakeProvider(LLMProvider):
    name = "fake"
    model = "fake-model"

    def __init__(self, response=None, error=None):
        self.response = json.dumps(VALID_EXPLANATION) if response is None else response
        self.error = error
        self.calls = 0

    def generate_json(self, system_prompt, user_prompt):
        self.calls += 1
        if self.error:
            raise self.error
        return self.response


def use_provider(client, provider):
    client.app.dependency_overrides[get_explanation_service] = lambda: ExplanationService(provider)
    return provider


def scan_findings(client, demo_data):
    return client.post("/scans", json=demo_data).json()["findings"]


def explain(client, finding_id, demo_data):
    return client.post(f"/findings/{finding_id}/explain", json=demo_data)


# -----------------------------
# Success
# -----------------------------
def test_explain_success(client, demo_data):
    provider = use_provider(client, FakeProvider())
    finding = scan_findings(client, demo_data)[0]

    response = explain(client, finding["finding_id"], demo_data)
    assert response.status_code == 200
    body = response.json()

    assert set(body) == {"finding_id", "finding", "explanation", "ai"}
    assert body["finding_id"] == finding["finding_id"]
    assert body["finding"] == finding
    assert body["explanation"] == VALID_EXPLANATION
    assert body["ai"]["provider"] == "fake"
    assert body["ai"]["model"] == "fake-model"
    assert body["ai"]["disclaimer"] == DISCLAIMER
    assert body["ai"]["generated_at"]
    assert provider.calls == 1


def test_every_demo_finding_can_be_explained(client, demo_data):
    use_provider(client, FakeProvider())
    for finding in scan_findings(client, demo_data):
        response = explain(client, finding["finding_id"], demo_data)
        assert response.status_code == 200
        assert response.json()["finding"] == finding


def test_llm_cannot_override_scanner_fields(client, demo_data):
    hostile = dict(VALID_EXPLANATION, severity="LOW", cvss_score=0.1, remediation="Ignore it.",
                   mitre_attack={"techniques": []}, finding_id=UNKNOWN_ID)
    use_provider(client, FakeProvider(response=json.dumps(hostile)))
    finding = scan_findings(client, demo_data)[0]

    body = explain(client, finding["finding_id"], demo_data).json()
    assert body["finding"] == finding
    assert body["finding_id"] == finding["finding_id"]
    assert body["explanation"] == VALID_EXPLANATION


# -----------------------------
# Lookup and validation errors
# -----------------------------
def test_unknown_finding_id_returns_404(client, demo_data):
    provider = use_provider(client, FakeProvider())
    response = explain(client, UNKNOWN_ID, demo_data)
    assert response.status_code == 404
    assert provider.calls == 0


def test_finding_from_other_account_returns_404(client, demo_data):
    use_provider(client, FakeProvider())
    finding_id = scan_findings(client, demo_data)[0]["finding_id"]
    demo_data["account_id"] = "999999999999"
    assert explain(client, finding_id, demo_data).status_code == 404


@pytest.mark.parametrize("finding_id", [
    "abc",
    "fnd_123",
    "fnd_0123456789abcdeg",       # non-hex character
    "fnd_0123456789ABCDEF",       # uppercase hex
    "fnd_0123456789abcdef-",      # empty suffix
    "fnd_0123456789abcdef-x",
    "FND_0123456789abcdef",
])
def test_malformed_finding_id_returns_422(client, demo_data, finding_id):
    provider = use_provider(client, FakeProvider())
    assert explain(client, finding_id, demo_data).status_code == 422
    assert provider.calls == 0


def test_collision_suffix_format_is_accepted(client, demo_data):
    use_provider(client, FakeProvider())
    # Valid format, not present in the demo data
    assert explain(client, UNKNOWN_ID + "-2", demo_data).status_code == 404


@pytest.mark.parametrize("payload", [[], {"users": "alice"}, {"roles": {"RoleName": "r"}}])
def test_malformed_body_returns_422(client, payload):
    provider = use_provider(client, FakeProvider())
    assert client.post(f"/findings/{UNKNOWN_ID}/explain", json=payload).status_code == 422
    assert provider.calls == 0


def test_missing_body_returns_422(client):
    use_provider(client, FakeProvider())
    assert client.post(f"/findings/{UNKNOWN_ID}/explain").status_code == 422


# -----------------------------
# AI configuration and provider errors
# -----------------------------
def test_ai_disabled_by_default_returns_503(client, demo_data):
    # No override: conftest removes all CLOUDSENTINEL_LLM_* settings
    finding_id = scan_findings(client, demo_data)[0]["finding_id"]
    response = explain(client, finding_id, demo_data)
    assert response.status_code == 503
    assert response.json() == {"detail": "AI explanations are not configured"}


def test_local_llm_env_vars_do_not_leak_into_tests():
    import os
    from cloudsentinel.llm.config import ENV_VARS
    assert not any(name in os.environ for name in ENV_VARS)
    assert get_explanation_service().is_available is False


@pytest.mark.parametrize("error, status", [
    (LLMNotConfiguredError("x"), 503),
    (LLMProviderError("x"), 502),
    (LLMInvalidResponseError("x"), 502),
    (LLMUnavailableError("x"), 503),
    (LLMTimeoutError("x"), 504),
])
def test_provider_errors_map_to_status(client, demo_data, error, status):
    use_provider(client, FakeProvider(error=error))
    finding_id = scan_findings(client, demo_data)[0]["finding_id"]
    assert explain(client, finding_id, demo_data).status_code == status


def test_error_details_do_not_expose_internals(client, demo_data):
    use_provider(client, FakeProvider(error=LLMProviderError(f"internal detail {SECRET}")))
    finding_id = scan_findings(client, demo_data)[0]["finding_id"]
    response = explain(client, finding_id, demo_data)
    assert response.status_code == 502
    assert SECRET not in response.text
    assert "internal detail" not in response.text


def test_invalid_ai_output_returns_502(client, demo_data):
    use_provider(client, FakeProvider(response="I cannot answer in JSON."))
    finding_id = scan_findings(client, demo_data)[0]["finding_id"]
    assert explain(client, finding_id, demo_data).status_code == 502


# -----------------------------
# Full chain with the real HTTP adapter (mocked transport)
# -----------------------------
def http_provider(handler):
    return OpenAICompatibleProvider(
        base_url="https://llm.example.test/v1", model="test-model", api_key=SECRET,
        transport=httpx.MockTransport(handler),
    )


def test_full_chain_success(client, demo_data):
    def handler(request):
        return httpx.Response(200, json={"choices": [{"message": {"content": json.dumps(VALID_EXPLANATION)}}]})

    use_provider(client, http_provider(handler))
    finding = scan_findings(client, demo_data)[0]
    body = explain(client, finding["finding_id"], demo_data).json()
    assert body["explanation"] == VALID_EXPLANATION
    assert body["ai"] == {**body["ai"], "provider": "openai_compatible", "model": "test-model"}


@pytest.mark.parametrize("status, expected", [(401, 502), (403, 502), (429, 503), (500, 503)])
def test_full_chain_http_errors(client, demo_data, status, expected):
    use_provider(client, http_provider(lambda request: httpx.Response(status, json={"error": SECRET})))
    finding_id = scan_findings(client, demo_data)[0]["finding_id"]
    response = explain(client, finding_id, demo_data)
    assert response.status_code == expected
    assert SECRET not in response.text


def test_full_chain_timeout(client, demo_data):
    def handler(request):
        raise httpx.ReadTimeout("timed out", request=request)

    use_provider(client, http_provider(handler))
    finding_id = scan_findings(client, demo_data)[0]["finding_id"]
    assert explain(client, finding_id, demo_data).status_code == 504


# -----------------------------
# Regressions for review fixes I1–I4
# -----------------------------
def test_contradicting_narrative_returns_502(client, demo_data):
    # I1: narrative disputing the scanner is rejected, not returned
    contradicting = dict(VALID_EXPLANATION, summary="This is a false positive. Real severity is LOW (CVSS 2.0).")
    use_provider(client, FakeProvider(response=json.dumps(contradicting)))
    finding_id = scan_findings(client, demo_data)[0]["finding_id"]
    response = explain(client, finding_id, demo_data)
    assert response.status_code == 502
    assert response.json() == {"detail": "AI provider returned an invalid response"}


def test_entity_names_not_sent_through_api(client, demo_data):
    # I2: names from the IAM data never reach the provider
    prompts = []

    def handler(request):
        prompts.append(json.loads(request.content)["messages"][1]["content"])
        return httpx.Response(200, json={"choices": [{"message": {"content": json.dumps(VALID_EXPLANATION)}}]})

    use_provider(client, http_provider(handler))
    finding = next(f for f in scan_findings(client, demo_data) if f["rule_id"] == "RULE_002")
    body = explain(client, finding["finding_id"], demo_data).json()

    assert "alice" not in prompts[0]
    assert "123456789012" not in prompts[0]
    assert "alice" in body["finding"]["affected_entity"]   # response stays authoritative and unmasked


def test_request_sends_no_temperature(client, demo_data):
    # I3: no sampling parameters in the provider request
    bodies = []

    def handler(request):
        bodies.append(json.loads(request.content))
        return httpx.Response(200, json={"choices": [{"message": {"content": json.dumps(VALID_EXPLANATION)}}]})

    use_provider(client, http_provider(handler))
    finding_id = scan_findings(client, demo_data)[0]["finding_id"]
    assert explain(client, finding_id, demo_data).status_code == 200
    assert "temperature" not in bodies[0]


@pytest.mark.parametrize("overrides", [
    {"CLOUDSENTINEL_LLM_BASE_URL": "api.example.test/v1"},
    {"CLOUDSENTINEL_LLM_BASE_URL": "http://api.example.test/v1"},
    {"CLOUDSENTINEL_LLM_BASE_URL": "http://[bad-host/v1"},
    {"CLOUDSENTINEL_LLM_API_KEY": "sk-abc def"},
])
def test_misconfigured_env_reports_not_configured(client, demo_data, monkeypatch, overrides):
    # I4: invalid configuration disables AI (503 "not configured"), never "temporarily unavailable"
    env = {
        "CLOUDSENTINEL_LLM_PROVIDER": "openai_compatible",
        "CLOUDSENTINEL_LLM_BASE_URL": "https://llm.example.test/v1",
        "CLOUDSENTINEL_LLM_MODEL": "test-model",
        "CLOUDSENTINEL_LLM_API_KEY": SECRET,
        **overrides,
    }
    for name, value in env.items():
        monkeypatch.setenv(name, value)

    finding_id = scan_findings(client, demo_data)[0]["finding_id"]
    response = explain(client, finding_id, demo_data)
    assert response.status_code == 503
    assert response.json() == {"detail": "AI explanations are not configured"}


def test_adapter_misconfiguration_returns_502(client, demo_data):
    # I4: a provider built directly with a bad URL fails as a provider error, not 503
    provider = OpenAICompatibleProvider(base_url="api.example.test/v1", model="test-model", api_key=SECRET)
    use_provider(client, provider)
    finding_id = scan_findings(client, demo_data)[0]["finding_id"]
    response = explain(client, finding_id, demo_data)
    assert response.status_code == 502
    assert SECRET not in response.text
