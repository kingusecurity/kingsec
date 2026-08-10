"""Unit tests for provider abstraction and selection."""

from __future__ import annotations

import pytest

from kingsec.infrastructure.ai import resolve_provider, supported_providers
from kingsec.infrastructure.ai.errors import AIError, AIResponseError
from kingsec.infrastructure.ai.providers import (
    AnthropicProvider,
    GeminiProvider,
    OpenAICompatibleProvider,
    default_model_for,
)


class TestSelection:
    def test_known_providers_resolve(self) -> None:
        assert isinstance(resolve_provider("openai"), OpenAICompatibleProvider)
        assert isinstance(resolve_provider("openrouter"), OpenAICompatibleProvider)
        assert isinstance(resolve_provider("glm"), OpenAICompatibleProvider)
        assert isinstance(resolve_provider("anthropic"), AnthropicProvider)
        assert isinstance(resolve_provider("claude"), AnthropicProvider)
        assert isinstance(resolve_provider("gemini"), GeminiProvider)

    def test_selection_is_case_insensitive(self) -> None:
        assert isinstance(resolve_provider("OpenAI"), OpenAICompatibleProvider)

    def test_unknown_provider_raises(self) -> None:
        with pytest.raises(AIError, match="unsupported AI provider"):
            resolve_provider("skynet")

    def test_supported_list(self) -> None:
        assert "gemini" in supported_providers()


class TestShaping:
    def test_openai_shape(self) -> None:
        p = OpenAICompatibleProvider()
        assert p.build_endpoint("https://api.x/v1", "gpt") == "https://api.x/v1/chat/completions"
        assert p.build_headers("k")["Authorization"] == "Bearer k"
        payload = p.build_payload("sys", "usr", "gpt", 0.2, 100)
        assert payload["messages"][0]["role"] == "system"
        assert p.extract_text({"choices": [{"message": {"content": "hi"}}]}) == "hi"

    def test_anthropic_shape(self) -> None:
        p = AnthropicProvider()
        assert p.build_endpoint("https://api.anthropic.com", "claude").endswith("/v1/messages")
        assert p.build_headers("k")["x-api-key"] == "k"
        payload = p.build_payload("sys", "usr", "claude", 0.2, 100)
        assert payload["system"] == "sys"
        assert p.extract_text({"content": [{"text": "hi"}]}) == "hi"

    def test_gemini_shape(self) -> None:
        p = GeminiProvider()
        assert ":generateContent" in p.build_endpoint("https://g", "gemini-pro")
        assert p.build_headers("k")["x-goog-api-key"] == "k"
        payload = p.build_payload("sys", "usr", "gemini-pro", 0.2, 100)
        assert payload["systemInstruction"]["parts"][0]["text"] == "sys"
        text = p.extract_text({"candidates": [{"content": {"parts": [{"text": "hi"}]}}]})
        assert text == "hi"

    def test_malformed_response_shape_raises(self) -> None:
        with pytest.raises(AIResponseError):
            OpenAICompatibleProvider().extract_text({"unexpected": True})


class TestDefaultModelFor:
    """Every supported provider must default to a model it actually has -
    this is what the Gemini 404 fix depends on (see config_resolver.py)."""

    def test_every_supported_provider_has_its_own_default(self) -> None:
        for provider in supported_providers():
            model = default_model_for(provider)
            assert isinstance(model, str) and model

    def test_gemini_default_is_a_real_gemini_model_not_an_anthropic_one(self) -> None:
        assert default_model_for("gemini") == "gemini-1.5-flash"
        assert "claude" not in default_model_for("gemini")

    def test_case_insensitive(self) -> None:
        assert default_model_for("Gemini") == default_model_for("gemini")

    def test_unrecognised_provider_falls_back_to_anthropic_default(self) -> None:
        assert default_model_for("not-a-real-provider") == default_model_for("anthropic")
