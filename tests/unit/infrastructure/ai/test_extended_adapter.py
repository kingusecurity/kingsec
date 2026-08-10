"""Unit tests for ExtendedAIAdapter (chat/generate/health).

Regression coverage for a real bug: this adapter referenced
AIProviderAdapter._require_api_key()/._provider - attributes that no
longer exist since AIProviderAdapter moved to resolving provider/key/
model/base_url fresh per call via AIConfigResolver. Every chat/generate/
health call raised AttributeError. There was no prior test file for this
adapter at all, which is how it shipped broken.
"""

from __future__ import annotations

import json

import httpx
import pytest
from pydantic import SecretStr

from kingsec.infrastructure.ai import AIClient, AIProviderAdapter
from kingsec.infrastructure.ai.config_resolver import AIConfigResolver
from kingsec.infrastructure.ai.errors import AIAuthenticationError
from kingsec.infrastructure.ai.extended_adapter import ExtendedAIAdapter
from kingsec.infrastructure.config.models import AISettings
from tests.unit.infrastructure.ai.conftest import transport_from
from tests.unit.infrastructure.ai.test_adapter import (
    _NoDbConfigRepository,
    _UnusedEncryptionService,
)


def _extended_adapter(transport: httpx.MockTransport, settings: AISettings) -> ExtendedAIAdapter:
    client = AIClient(timeout=5, retry_count=0, retry_delay=0, transport=transport)
    resolver = AIConfigResolver(settings, _NoDbConfigRepository(), _UnusedEncryptionService())
    inner = AIProviderAdapter(settings=settings, config_resolver=resolver, client=client)
    return ExtendedAIAdapter(inner)


def _openai_text_response(text: str) -> httpx.Response:
    return httpx.Response(200, json={"choices": [{"message": {"content": text}}]})


class TestGenerate:
    def test_returns_provider_text(self) -> None:
        captured: dict = {}

        def handler(request: httpx.Request) -> httpx.Response:
            captured["body"] = json.loads(request.content)
            return _openai_text_response("hello from the model")

        adapter = _extended_adapter(
            transport_from(handler),
            AISettings(provider="openai", api_key=SecretStr("k"), base_url="http://api.test"),
        )
        result = adapter.generate("system", "user prompt")

        assert result == "hello from the model"
        assert captured["body"]["messages"][0]["role"] == "system"

    def test_missing_api_key_raises_ai_authentication_error(self) -> None:
        adapter = _extended_adapter(
            transport_from(lambda r: _openai_text_response("unused")),
            AISettings(provider="openai", base_url="http://t"),  # no api_key
        )
        with pytest.raises(AIAuthenticationError):
            adapter.generate("system", "user")


class TestChat:
    def test_sends_last_user_message_and_returns_text(self) -> None:
        captured: dict = {}

        def handler(request: httpx.Request) -> httpx.Response:
            captured["body"] = json.loads(request.content)
            return _openai_text_response("chat reply")

        adapter = _extended_adapter(
            transport_from(handler),
            AISettings(provider="openai", api_key=SecretStr("k"), base_url="http://api.test"),
        )
        result = adapter.chat(
            [
                {"role": "system", "content": "You are helpful."},
                {"role": "user", "content": "What is a CVSS score?"},
            ]
        )

        assert result == "chat reply"
        assert captured["body"]["messages"][1]["content"] == "What is a CVSS score?"

    def test_missing_api_key_raises_ai_authentication_error(self) -> None:
        adapter = _extended_adapter(
            transport_from(lambda r: _openai_text_response("unused")),
            AISettings(provider="openai", base_url="http://t"),  # no api_key
        )
        with pytest.raises(AIAuthenticationError):
            adapter.chat([{"role": "user", "content": "hi"}])


class TestHealth:
    def test_available_when_provider_responds(self) -> None:
        adapter = _extended_adapter(
            transport_from(lambda r: _openai_text_response("OK")),
            AISettings(provider="openai", api_key=SecretStr("k"), base_url="http://t"),
        )
        result = adapter.health()

        assert result["available"] is True
        assert result["provider"] == "openai"

    def test_unavailable_without_a_configured_key_instead_of_crashing(self) -> None:
        """The exact scenario that used to crash: no key configured, so
        the underlying call raises - health() must degrade gracefully,
        not propagate an AttributeError from a stale attribute access."""
        adapter = _extended_adapter(
            transport_from(lambda r: _openai_text_response("unused")),
            AISettings(provider="openai", base_url="http://t"),  # no api_key
        )
        result = adapter.health()

        assert result["available"] is False
        assert result["provider"] == "openai"
        assert "error" in result
