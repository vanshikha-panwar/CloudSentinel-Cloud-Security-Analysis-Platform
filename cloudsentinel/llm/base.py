"""
LLM provider abstraction.

The rest of CloudSentinel depends only on LLMProvider and the exceptions
below, never on a specific vendor. Exception messages must never contain
API keys or raw provider responses.
"""

from abc import ABC, abstractmethod
from typing import Optional


class LLMError(Exception):
    """Base class for all LLM provider errors."""


class LLMNotConfiguredError(LLMError):
    """No usable LLM provider is configured."""


class LLMProviderError(LLMError):
    """Provider rejected the request (e.g. authentication failure, bad request)."""


class LLMUnavailableError(LLMError):
    """Provider is temporarily unavailable (rate limited, server error, connection failure)."""


class LLMTimeoutError(LLMError):
    """Provider did not respond in time."""


class LLMInvalidResponseError(LLMError):
    """Provider responded, but the response is not in the expected format."""


class LLMProvider(ABC):
    """A text-generation backend that returns a JSON document as a string."""

    name: str = "unknown"
    model: Optional[str] = None
    configured: bool = True

    @abstractmethod
    def generate_json(self, system_prompt: str, user_prompt: str) -> str:
        """
        Return the model's reply, expected to be a JSON object as text.

        Raises:
            LLMError subclasses on any failure.
        """


class DisabledProvider(LLMProvider):
    """Placeholder used when AI explanations are turned off or misconfigured."""

    name = "disabled"
    model = None
    configured = False

    def generate_json(self, system_prompt: str, user_prompt: str) -> str:
        raise LLMNotConfiguredError("AI explanations are not configured")
