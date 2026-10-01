"""
OpenAI-compatible chat completions adapter.

Works with any provider exposing POST {base_url}/chat/completions in the
OpenAI format (e.g. OpenAI, Google Gemini's OpenAI-compatible endpoint,
Groq, OpenRouter, local Ollama). Uses httpx directly; no vendor SDK.

No sampling parameters (e.g. temperature) are sent: some models only accept
their defaults and reject the request otherwise. Output reliability comes
from strict validation in ExplanationService instead.
"""

from typing import Optional

import httpx

from .base import (
    LLMInvalidResponseError,
    LLMProvider,
    LLMProviderError,
    LLMTimeoutError,
    LLMUnavailableError,
)


class OpenAICompatibleProvider(LLMProvider):
    """LLMProvider backed by an OpenAI-compatible /chat/completions endpoint."""

    name = "openai_compatible"

    def __init__(
        self,
        base_url: str,
        model: str,
        api_key: str,
        timeout_seconds: float = 20.0,
        transport: Optional[httpx.BaseTransport] = None,
    ):
        """
        Args:
            transport: Optional httpx transport; tests pass httpx.MockTransport.
        """
        self.model = model
        self._url = base_url.rstrip("/") + "/chat/completions"
        self._api_key = api_key
        self._timeout = timeout_seconds
        self._transport = transport

    def __repr__(self) -> str:
        # Never include the API key
        return f"OpenAICompatibleProvider(url={self._url!r}, model={self.model!r})"

    def generate_json(self, system_prompt: str, user_prompt: str) -> str:
        payload = {
            "model": self.model,
            "messages": [
                {"role": "system", "content": system_prompt},
                {"role": "user", "content": user_prompt},
            ],
        }
        headers = {"Authorization": f"Bearer {self._api_key}"}

        try:
            with httpx.Client(timeout=self._timeout, transport=self._transport) as client:
                response = client.post(self._url, json=payload, headers=headers)
        except httpx.TimeoutException:
            raise LLMTimeoutError("LLM provider request timed out") from None
        except httpx.UnsupportedProtocol:
            # Misconfigured base URL (e.g. missing scheme): retrying won't help
            raise LLMProviderError("LLM provider URL is invalid") from None
        except httpx.TransportError:
            raise LLMUnavailableError("Could not connect to LLM provider") from None
        except (httpx.HTTPError, httpx.InvalidURL, ValueError):
            # Request could not be built or sent, e.g. invalid URL or a
            # non-ASCII API key (UnicodeEncodeError is a ValueError)
            raise LLMProviderError("LLM provider request could not be sent") from None

        status = response.status_code
        if status in (401, 403):
            raise LLMProviderError(f"LLM provider rejected the credentials (HTTP {status})")
        if status == 429:
            raise LLMUnavailableError("LLM provider rate limit reached (HTTP 429)")
        if status >= 500:
            raise LLMUnavailableError(f"LLM provider server error (HTTP {status})")
        if status != 200:
            raise LLMProviderError(f"LLM provider request failed (HTTP {status})")

        try:
            content = response.json()["choices"][0]["message"]["content"]
        except (ValueError, KeyError, IndexError, TypeError):
            raise LLMInvalidResponseError("LLM provider response is not a chat completion") from None

        if not isinstance(content, str) or not content.strip():
            raise LLMInvalidResponseError("LLM provider returned an empty message")
        return content
