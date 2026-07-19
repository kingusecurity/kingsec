"""KingSec AI enrichment adapter (infrastructure layer).

Implements the application's ``AIPort`` by calling a configurable, provider-
agnostic AI backend over HTTPS (httpx) and mapping the reply onto a domain
``Recommendation``.

Public API
    Adapter:    AIProviderAdapter
    Client:     AIClient
    Prompt:     PromptBuilder, sanitize, SYSTEM_PROMPT
    Parsing:    ResponseParser, Enrichment
    Providers:  ProviderConfig, resolve_provider, supported_providers
    Errors:     AIError, AITimeoutError, AIAuthenticationError,
                AIRateLimitError, AIResponseError, ErrorTranslator
    DI wiring:  register_ai
"""

from __future__ import annotations

from .adapter import AIProviderAdapter
from .client import AIClient
from .errors import (
    AIAuthenticationError,
    AIError,
    AIRateLimitError,
    AIResponseError,
    AITimeoutError,
    ErrorTranslator,
)
from .parser import Enrichment, ResponseParser
from .prompt import SYSTEM_PROMPT, PromptBuilder, sanitize
from .providers import (
    ProviderConfig,
    resolve_provider,
    supported_providers,
)
from .provisioning import register_ai

__all__ = [
    "SYSTEM_PROMPT",
    "AIAuthenticationError",
    "AIClient",
    "AIError",
    "AIProviderAdapter",
    "AIRateLimitError",
    "AIResponseError",
    "AITimeoutError",
    "Enrichment",
    "ErrorTranslator",
    "PromptBuilder",
    "ProviderConfig",
    "ResponseParser",
    "register_ai",
    "resolve_provider",
    "sanitize",
    "supported_providers",
]
