"""
Tests for the OpenAI-compatible LLM adapter and LLM configuration.

All HTTP traffic goes through httpx.MockTransport; no real network calls.
"""

import json
import logging

import httpx
import pytest

from cloudsentinel.llm import (
    DisabledProvider,
    LLMInvalidResponseError,
    LLMNotConfiguredError,
    LLMProviderError,
    LLMSettings,
    LLMTimeoutError,
    LLMUnavailableError,
    OpenAICompatibleProvider,
    build_provider,
)

API_KEY = "sk-test-SECRET-key-123"
BASE_URL = "https://llm.example.test/v1"
MODEL = "test-model"


def completion(content):
    return {"choices": [{"message": {"role": "assistant", "content": content}}]}


def make_provider(handler, base_url=BASE_URL):
    return OpenAICompatibleProvider(
        base_url=base_url, model=MODEL, api_key=API_KEY,
        timeout_seconds=5, transport=httpx.MockTransport(handler),
    )


# -----------------------------
# Successful requests
# -----------------------------
def test_returns_message_content():
    provider = make_provider(lambda request: httpx.Response(200, json=completion('{"summary": "x"}')))
    assert provider.generate_json("system", "user") == '{"summary": "x"}'


def test_request_format():
    captured = {}

    def handler(request):
        captured["request"] = request
        return httpx.Response(200, json=completion("{}"))

    make_provider(handler).generate_json("SYSTEM PROMPT", "USER PROMPT")
    request = captured["request"]
    body = json.loads(request.content)

    assert request.method == "POST"
    assert str(request.url) == f"{BASE_URL}/chat/completions"
    assert request.headers["Authorization"] == f"Bearer {API_KEY}"
    assert body["model"] == MODEL
    assert body["messages"] == [
        {"role": "system", "content": "SYSTEM PROMPT"},
        {"role": "user", "content": "USER PROMPT"},
    ]


def test_no_sampling_parameters_sent():
    # Regression (I3): some models reject any non-default temperature
    captured = {}

    def handler(request):
        captured["body"] = json.loads(request.content)
        return httpx.Response(200, json=completion("{}"))

    make_provider(handler).generate_json("s", "u")
    assert set(captured["body"]) == {"model", "messages"}
    assert "temperature" not in captured["body"]


def test_trailing_slash_in_base_url():
    captured = {}

    def handler(request):
        captured["url"] = str(request.url)
        return httpx.Response(200, json=completion("{}"))

    make_provider(handler, base_url=BASE_URL + "/").generate_json("s", "u")
    assert captured["url"] == f"{BASE_URL}/chat/completions"


# -----------------------------
# HTTP errors
# -----------------------------
@pytest.mark.parametrize("status", [401, 403])
def test_auth_errors(status):
    provider = make_provider(lambda request: httpx.Response(status, json={"error": {"message": "bad key " + API_KEY}}))
    with pytest.raises(LLMProviderError) as exc_info:
        provider.generate_json("s", "u")
    assert API_KEY not in str(exc_info.value)
    assert "bad key" not in str(exc_info.value)


@pytest.mark.parametrize("status", [400, 404])
def test_other_client_errors(status):
    provider = make_provider(lambda request: httpx.Response(status, json={"error": "model not found"}))
    with pytest.raises(LLMProviderError):
        provider.generate_json("s", "u")


@pytest.mark.parametrize("status", [429, 500, 502, 503])
def test_rate_limit_and_server_errors(status):
    provider = make_provider(lambda request: httpx.Response(status))
    with pytest.raises(LLMUnavailableError):
        provider.generate_json("s", "u")


def test_unavailable_is_not_a_provider_error():
    # Distinct types so the API can map them to 503 vs 502
    assert not issubclass(LLMUnavailableError, LLMProviderError)


# -----------------------------
# Transport errors
# -----------------------------
@pytest.mark.parametrize("error", [httpx.ReadTimeout, httpx.ConnectTimeout])
def test_timeout(error):
    def handler(request):
        raise error("timed out", request=request)

    with pytest.raises(LLMTimeoutError):
        make_provider(handler).generate_json("s", "u")


def test_connection_error():
    def handler(request):
        raise httpx.ConnectError("connection refused", request=request)

    with pytest.raises(LLMUnavailableError):
        make_provider(handler).generate_json("s", "u")


# -----------------------------
# Misconfiguration in the adapter (I4 regression)
# -----------------------------
@pytest.mark.parametrize("transport", [httpx.MockTransport(lambda request: httpx.Response(200)), None])
def test_url_without_scheme_is_provider_error_not_unavailable(transport):
    # Fails before any connection attempt, with both mock and real transports
    provider = OpenAICompatibleProvider("api.example.test/v1", MODEL, API_KEY, timeout_seconds=1, transport=transport)
    with pytest.raises(LLMProviderError) as exc_info:
        provider.generate_json("s", "u")
    assert not isinstance(exc_info.value, LLMUnavailableError)


def test_non_ascii_api_key_is_mapped_and_not_leaked():
    key = API_KEY + "é"
    provider = OpenAICompatibleProvider(BASE_URL, MODEL, key, transport=httpx.MockTransport(lambda r: httpx.Response(200)))
    with pytest.raises(LLMProviderError) as exc_info:
        provider.generate_json("s", "u")
    assert key not in str(exc_info.value)
    assert API_KEY not in str(exc_info.value)


def test_other_httpx_errors_are_mapped():
    def handler(request):
        raise httpx.TooManyRedirects("redirect loop", request=request)

    with pytest.raises(LLMProviderError):
        make_provider(handler).generate_json("s", "u")


# -----------------------------
# Malformed responses
# -----------------------------
@pytest.mark.parametrize("response", [
    httpx.Response(200, content=b"<html>not json</html>"),
    httpx.Response(200, json={"unexpected": True}),
    httpx.Response(200, json={"choices": []}),
    httpx.Response(200, json={"choices": [{"message": {"content": None}}]}),
    httpx.Response(200, json=completion("   ")),
])
def test_malformed_responses(response):
    provider = make_provider(lambda request: response)
    with pytest.raises(LLMInvalidResponseError):
        provider.generate_json("s", "u")


def test_repr_hides_api_key():
    provider = make_provider(lambda request: httpx.Response(200))
    assert API_KEY not in repr(provider)


# -----------------------------
# Configuration
# -----------------------------
FULL_ENV = {
    "CLOUDSENTINEL_LLM_PROVIDER": "openai_compatible",
    "CLOUDSENTINEL_LLM_BASE_URL": BASE_URL,
    "CLOUDSENTINEL_LLM_MODEL": MODEL,
    "CLOUDSENTINEL_LLM_API_KEY": API_KEY,
    "CLOUDSENTINEL_LLM_TIMEOUT_SECONDS": "7",
}


def test_default_is_disabled():
    provider = build_provider(LLMSettings.from_env({}))
    assert isinstance(provider, DisabledProvider)
    assert provider.configured is False
    with pytest.raises(LLMNotConfiguredError):
        provider.generate_json("s", "u")


def test_full_configuration_builds_openai_compatible_provider():
    settings = LLMSettings.from_env(FULL_ENV)
    provider = build_provider(settings)
    assert isinstance(provider, OpenAICompatibleProvider)
    assert provider.model == MODEL
    assert provider.configured is True
    assert settings.timeout_seconds == 7.0


def test_provider_name_is_case_insensitive():
    env = dict(FULL_ENV, CLOUDSENTINEL_LLM_PROVIDER="OpenAI_Compatible")
    assert isinstance(build_provider(LLMSettings.from_env(env)), OpenAICompatibleProvider)


@pytest.mark.parametrize("missing", [
    "CLOUDSENTINEL_LLM_API_KEY",
    "CLOUDSENTINEL_LLM_MODEL",
    "CLOUDSENTINEL_LLM_BASE_URL",
])
def test_missing_setting_disables_ai(missing, caplog):
    env = {k: v for k, v in FULL_ENV.items() if k != missing}
    with caplog.at_level(logging.WARNING):
        provider = build_provider(LLMSettings.from_env(env))
    assert isinstance(provider, DisabledProvider)
    assert missing in caplog.text
    assert API_KEY not in caplog.text


def test_blank_values_count_as_missing():
    env = dict(FULL_ENV, CLOUDSENTINEL_LLM_API_KEY="   ")
    assert isinstance(build_provider(LLMSettings.from_env(env)), DisabledProvider)


def test_unknown_provider_disables_ai(caplog):
    env = dict(FULL_ENV, CLOUDSENTINEL_LLM_PROVIDER="gemini-native")
    with caplog.at_level(logging.WARNING):
        provider = build_provider(LLMSettings.from_env(env))
    assert isinstance(provider, DisabledProvider)
    assert API_KEY not in caplog.text


@pytest.mark.parametrize("value", ["abc", "0", "-5"])
def test_invalid_timeout_uses_default(value):
    settings = LLMSettings.from_env(dict(FULL_ENV, CLOUDSENTINEL_LLM_TIMEOUT_SECONDS=value))
    assert settings.timeout_seconds == 20.0


def test_settings_repr_hides_api_key():
    assert API_KEY not in repr(LLMSettings.from_env(FULL_ENV))


@pytest.mark.parametrize("base_url", [
    "api.example.test/v1",                        # no scheme
    "ftp://api.example.test/v1",                  # unsupported scheme
    "http://api.example.test/v1",                 # plain http to a remote host
    "http://[bad-host/v1",                        # unparsable
    "https://exa mple.test/v1",                   # whitespace in host
    "https:///v1",                                # no host
    "https://api.example.test/v1?key=QUERYSECRET",
    "https://api.example.test/v1#fragment",
])
def test_invalid_base_url_disables_ai(base_url, caplog):
    # Regression (I4): misconfiguration must not surface as "temporarily unavailable"
    with caplog.at_level(logging.WARNING):
        provider = build_provider(LLMSettings.from_env(dict(FULL_ENV, CLOUDSENTINEL_LLM_BASE_URL=base_url)))
    assert isinstance(provider, DisabledProvider)
    assert "CLOUDSENTINEL_LLM_BASE_URL" in caplog.text
    assert base_url not in caplog.text
    assert "QUERYSECRET" not in caplog.text
    assert API_KEY not in caplog.text


@pytest.mark.parametrize("base_url", [
    "https://api.example.test/v1",
    "HTTPS://API.EXAMPLE.TEST/v1",
    "http://localhost:11434/v1",
    "http://127.0.0.1:8012/v1",
    "http://[::1]:8080/v1",
])
def test_valid_base_url_accepted(base_url):
    provider = build_provider(LLMSettings.from_env(dict(FULL_ENV, CLOUDSENTINEL_LLM_BASE_URL=base_url)))
    assert isinstance(provider, OpenAICompatibleProvider)


@pytest.mark.parametrize("api_key", ["sk-abcé123", "sk-abc def", "sk-abc\ndef", "sk-abc\tdef", "sk-abc\x00def"])
def test_invalid_api_key_disables_ai(api_key, caplog):
    with caplog.at_level(logging.WARNING):
        provider = build_provider(LLMSettings.from_env(dict(FULL_ENV, CLOUDSENTINEL_LLM_API_KEY=api_key)))
    assert isinstance(provider, DisabledProvider)
    assert "CLOUDSENTINEL_LLM_API_KEY" in caplog.text
    assert "sk-abc" not in caplog.text


def test_from_env_reads_process_environment(monkeypatch):
    for name, value in FULL_ENV.items():
        monkeypatch.setenv(name, value)
    assert isinstance(build_provider(), OpenAICompatibleProvider)
