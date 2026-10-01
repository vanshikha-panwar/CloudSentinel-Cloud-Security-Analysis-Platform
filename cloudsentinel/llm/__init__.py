"""
Vendor-neutral LLM provider layer for AI-assisted explanations.
"""

from .base import (
    DisabledProvider,
    LLMError,
    LLMInvalidResponseError,
    LLMNotConfiguredError,
    LLMProvider,
    LLMProviderError,
    LLMTimeoutError,
    LLMUnavailableError,
)
from .config import LLMSettings, build_provider
from .openai_compatible import OpenAICompatibleProvider

__all__ = [
    "LLMProvider",
    "DisabledProvider",
    "OpenAICompatibleProvider",
    "LLMSettings",
    "build_provider",
    "LLMError",
    "LLMNotConfiguredError",
    "LLMProviderError",
    "LLMUnavailableError",
    "LLMTimeoutError",
    "LLMInvalidResponseError",
]
