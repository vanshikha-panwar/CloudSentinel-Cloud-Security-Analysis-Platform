"""
LLM configuration from environment variables.

    CLOUDSENTINEL_LLM_PROVIDER         disabled (default) | openai_compatible
    CLOUDSENTINEL_LLM_BASE_URL         e.g. https://api.openai.com/v1
    CLOUDSENTINEL_LLM_MODEL            e.g. gpt-4o-mini
    CLOUDSENTINEL_LLM_API_KEY          secret, never logged
    CLOUDSENTINEL_LLM_TIMEOUT_SECONDS  default 20

Incomplete or invalid configuration disables AI explanations with a warning;
it never prevents the application from starting. The base URL has no
default, so a key can't be sent to the wrong vendor by accident. The base
URL must use https (plain http is allowed only for a local server), and
the key must be printable ASCII. Warnings never include the base URL or key.
"""

import logging
import os
from dataclasses import dataclass, field
from typing import Mapping, Optional
from urllib.parse import urlsplit

from .base import DisabledProvider, LLMProvider
from .openai_compatible import OpenAICompatibleProvider

logger = logging.getLogger(__name__)

ENV_PROVIDER = "CLOUDSENTINEL_LLM_PROVIDER"
ENV_BASE_URL = "CLOUDSENTINEL_LLM_BASE_URL"
ENV_MODEL = "CLOUDSENTINEL_LLM_MODEL"
ENV_API_KEY = "CLOUDSENTINEL_LLM_API_KEY"
ENV_TIMEOUT = "CLOUDSENTINEL_LLM_TIMEOUT_SECONDS"
ENV_VARS = (ENV_PROVIDER, ENV_BASE_URL, ENV_MODEL, ENV_API_KEY, ENV_TIMEOUT)

PROVIDER_DISABLED = "disabled"
PROVIDER_OPENAI_COMPATIBLE = "openai_compatible"
DEFAULT_TIMEOUT_SECONDS = 20.0

# Plain http is only allowed to these hosts (e.g. a local Ollama server)
LOOPBACK_HOSTS = ("localhost", "127.0.0.1", "::1")


def base_url_problem(base_url: str) -> Optional[str]:
    """Return why base_url is unusable, or None if it is acceptable."""
    try:
        parts = urlsplit(base_url)
        host = parts.hostname
    except ValueError:
        return "is not a valid URL"
    if parts.scheme not in ("https", "http"):
        return "must start with https://"
    if not host or any(c.isspace() for c in host):
        return "has no valid host"
    if parts.scheme == "http" and host not in LOOPBACK_HOSTS:
        return "must use https:// unless the server is on localhost"
    if parts.query or parts.fragment:
        return "must not contain a query string or fragment"
    return None


def api_key_problem(api_key: str) -> Optional[str]:
    """Return why api_key is unusable, or None. Never includes the key."""
    if not api_key.isascii() or not api_key.isprintable() or any(c.isspace() for c in api_key):
        return "contains unsupported characters (expected printable ASCII without spaces)"
    return None


@dataclass(frozen=True)
class LLMSettings:
    provider: str = PROVIDER_DISABLED
    base_url: Optional[str] = None
    model: Optional[str] = None
    api_key: Optional[str] = field(default=None, repr=False)
    timeout_seconds: float = DEFAULT_TIMEOUT_SECONDS

    @classmethod
    def from_env(cls, environ: Optional[Mapping[str, str]] = None) -> "LLMSettings":
        env = os.environ if environ is None else environ

        def get(name: str) -> Optional[str]:
            value = env.get(name, "").strip()
            return value or None

        timeout = DEFAULT_TIMEOUT_SECONDS
        raw_timeout = get(ENV_TIMEOUT)
        if raw_timeout is not None:
            try:
                timeout = float(raw_timeout)
                if timeout <= 0:
                    raise ValueError
            except ValueError:
                logger.warning("Invalid %s value; using default of %s seconds", ENV_TIMEOUT, DEFAULT_TIMEOUT_SECONDS)
                timeout = DEFAULT_TIMEOUT_SECONDS

        return cls(
            provider=(get(ENV_PROVIDER) or PROVIDER_DISABLED).lower(),
            base_url=get(ENV_BASE_URL),
            model=get(ENV_MODEL),
            api_key=get(ENV_API_KEY),
            timeout_seconds=timeout,
        )


def build_provider(settings: Optional[LLMSettings] = None) -> LLMProvider:
    """Create the configured provider, or a DisabledProvider if configuration is incomplete."""
    settings = settings or LLMSettings.from_env()

    if settings.provider == PROVIDER_DISABLED:
        return DisabledProvider()

    if settings.provider != PROVIDER_OPENAI_COMPATIBLE:
        logger.warning(
            "Unknown %s '%s'; AI explanations disabled. Supported: %s, %s",
            ENV_PROVIDER, settings.provider, PROVIDER_DISABLED, PROVIDER_OPENAI_COMPATIBLE,
        )
        return DisabledProvider()

    missing = [
        name for name, value in (
            (ENV_BASE_URL, settings.base_url),
            (ENV_MODEL, settings.model),
            (ENV_API_KEY, settings.api_key),
        )
        if not value
    ]
    if missing:
        logger.warning("AI explanations disabled; missing configuration: %s", ", ".join(missing))
        return DisabledProvider()

    for name, problem in (
        (ENV_BASE_URL, base_url_problem(settings.base_url)),
        (ENV_API_KEY, api_key_problem(settings.api_key)),
    ):
        if problem:
            logger.warning("AI explanations disabled; %s %s", name, problem)
            return DisabledProvider()

    return OpenAICompatibleProvider(
        base_url=settings.base_url,
        model=settings.model,
        api_key=settings.api_key,
        timeout_seconds=settings.timeout_seconds,
    )
