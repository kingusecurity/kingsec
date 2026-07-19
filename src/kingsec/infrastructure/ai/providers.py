"""Provider-agnostic request/response shaping.

Different AI providers speak different wire formats. A ``ProviderConfig`` strategy
encapsulates the four provider-specific concerns — endpoint URL, headers, request
payload, and response text extraction — behind one interface. The concrete
provider is selected entirely from configuration (``settings.ai.provider``); no
provider is privileged in code.

Supported out of the box:
    openai / openrouter / glm  -> OpenAI-compatible /chat/completions
    anthropic (a.k.a. claude)  -> /v1/messages
    gemini                     -> :generateContent
Adding a provider means adding one strategy and one registry entry.
"""

from __future__ import annotations

from abc import ABC, abstractmethod

from .errors import AIError, AIResponseError


class ProviderConfig(ABC):
    """Strategy describing how to talk to one AI provider."""

    name: str
    default_base_url: str

    @abstractmethod
    def build_endpoint(self, base_url: str, model: str) -> str:
        """Return the full request URL for a chat/completion call."""

    @abstractmethod
    def build_headers(self, api_key: str) -> dict[str, str]:
        """Return request headers, including authentication."""

    @abstractmethod
    def build_payload(
        self,
        system_prompt: str,
        user_prompt: str,
        model: str,
        temperature: float,
        max_tokens: int,
    ) -> dict:
        """Return the JSON request body."""

    @abstractmethod
    def extract_text(self, response: dict) -> str:
        """Extract the generated text from a parsed response body."""


def _extract(response: dict, *path) -> str:
    """Safely walk ``path`` (keys/indices) into ``response`` or raise AIResponseError."""
    node: object = response
    try:
        for step in path:
            node = node[step]  # type: ignore[index]
    except (KeyError, IndexError, TypeError) as exc:
        raise AIResponseError("unexpected AI response shape", cause=exc) from exc
    if not isinstance(node, str):
        raise AIResponseError("AI response text was not a string")
    return node


class OpenAICompatibleProvider(ProviderConfig):
    """OpenAI-style ``/chat/completions`` API (OpenAI, OpenRouter, GLM, ...)."""

    def __init__(self, name: str = "openai", default_base_url: str = "https://api.openai.com/v1") -> None:
        self.name = name
        self.default_base_url = default_base_url

    def build_endpoint(self, base_url: str, model: str) -> str:
        return f"{base_url.rstrip('/')}/chat/completions"

    def build_headers(self, api_key: str) -> dict[str, str]:
        return {"Authorization": f"Bearer {api_key}", "Content-Type": "application/json"}

    def build_payload(self, system_prompt, user_prompt, model, temperature, max_tokens) -> dict:
        return {
            "model": model,
            "messages": [
                {"role": "system", "content": system_prompt},
                {"role": "user", "content": user_prompt},
            ],
            "temperature": temperature,
            "max_tokens": max_tokens,
        }

    def extract_text(self, response: dict) -> str:
        return _extract(response, "choices", 0, "message", "content")


class AnthropicProvider(ProviderConfig):
    """Anthropic Claude ``/v1/messages`` API."""

    name = "anthropic"
    default_base_url = "https://api.anthropic.com"

    def build_endpoint(self, base_url: str, model: str) -> str:
        return f"{base_url.rstrip('/')}/v1/messages"

    def build_headers(self, api_key: str) -> dict[str, str]:
        return {
            "x-api-key": api_key,
            "anthropic-version": "2023-06-01",
            "Content-Type": "application/json",
        }

    def build_payload(self, system_prompt, user_prompt, model, temperature, max_tokens) -> dict:
        return {
            "model": model,
            "system": system_prompt,
            "messages": [{"role": "user", "content": user_prompt}],
            "max_tokens": max_tokens,
            "temperature": temperature,
        }

    def extract_text(self, response: dict) -> str:
        return _extract(response, "content", 0, "text")


class GeminiProvider(ProviderConfig):
    """Google Gemini ``:generateContent`` API."""

    name = "gemini"
    default_base_url = "https://generativelanguage.googleapis.com"

    def build_endpoint(self, base_url: str, model: str) -> str:
        return f"{base_url.rstrip('/')}/v1beta/models/{model}:generateContent"

    def build_headers(self, api_key: str) -> dict[str, str]:
        return {"x-goog-api-key": api_key, "Content-Type": "application/json"}

    def build_payload(self, system_prompt, user_prompt, model, temperature, max_tokens) -> dict:
        return {
            "systemInstruction": {"parts": [{"text": system_prompt}]},
            "contents": [{"role": "user", "parts": [{"text": user_prompt}]}],
            "generationConfig": {"temperature": temperature, "maxOutputTokens": max_tokens},
        }

    def extract_text(self, response: dict) -> str:
        return _extract(response, "candidates", 0, "content", "parts", 0, "text")


# Registry: provider name (from config) -> factory. Aliases share a strategy.
_PROVIDER_FACTORIES: dict[str, callable[[], ProviderConfig]] = {
    "openai": lambda: OpenAICompatibleProvider("openai", "https://api.openai.com/v1"),
    "openrouter": lambda: OpenAICompatibleProvider("openrouter", "https://openrouter.ai/api/v1"),
    "glm": lambda: OpenAICompatibleProvider("glm", "https://open.bigmodel.cn/api/paas/v4"),
    "anthropic": AnthropicProvider,
    "claude": AnthropicProvider,
    "gemini": GeminiProvider,
}


def resolve_provider(name: str) -> ProviderConfig:
    """Select a provider strategy by configured name.

    Args:
        name: The ``settings.ai.provider`` value (case-insensitive).

    Returns:
        The matching ``ProviderConfig``.

    Raises:
        AIError: If no provider matches the name.
    """
    factory = _PROVIDER_FACTORIES.get(name.strip().lower())
    if factory is None:
        supported = ", ".join(sorted(_PROVIDER_FACTORIES))
        raise AIError(
            f"unsupported AI provider {name!r}; supported: {supported}",
            context={"provider": name},
        )
    return factory()


def supported_providers() -> tuple[str, ...]:
    """Return the sorted names of all registered providers."""
    return tuple(sorted(_PROVIDER_FACTORIES))
