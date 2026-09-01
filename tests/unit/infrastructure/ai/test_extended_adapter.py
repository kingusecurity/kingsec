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
from cryptography.fernet import Fernet
from pydantic import SecretStr

import kingsec.infrastructure.ai.extended_adapter as extended_adapter_module
from kingsec.application.ports.outbound.ai_provider_config_repository import AIProviderConfigRecord
from kingsec.infrastructure.ai import AIClient, AIProviderAdapter
from kingsec.infrastructure.ai.config_resolver import AIConfigResolver
from kingsec.infrastructure.ai.errors import AIAuthenticationError, AIUnsafeURLError
from kingsec.infrastructure.ai.extended_adapter import ExtendedAIAdapter
from kingsec.infrastructure.config.models import AISettings
from kingsec.infrastructure.notifications.url_validator import SSRFURLValidator
from kingsec.infrastructure.secrets.fernet_encryption_service import FernetEncryptionService
from tests.unit.infrastructure.ai.conftest import transport_from
from tests.unit.infrastructure.ai.test_adapter import (
    _DbConfigRepository,
    _NoDbConfigRepository,
    _UnusedEncryptionService,
    _UnusedURLValidator,
)


def _extended_adapter(transport: httpx.MockTransport, settings: AISettings) -> ExtendedAIAdapter:
    client = AIClient(timeout=5, retry_count=0, retry_delay=0, transport=transport)
    resolver = AIConfigResolver(settings, _NoDbConfigRepository(), _UnusedEncryptionService())
    inner = AIProviderAdapter(
        settings=settings, config_resolver=resolver, client=client, url_validator=_UnusedURLValidator()
    )
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
            AISettings(provider="openai", api_key=SecretStr("k"), base_url="http://127.0.0.1"),
        )
        result = adapter.generate("system", "user prompt")

        assert result == "hello from the model"
        assert captured["body"]["messages"][0]["role"] == "system"

    def test_missing_api_key_raises_ai_authentication_error(self) -> None:
        adapter = _extended_adapter(
            transport_from(lambda r: _openai_text_response("unused")),
            AISettings(provider="openai", base_url="http://127.0.0.1"),  # no api_key
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
            AISettings(provider="openai", api_key=SecretStr("k"), base_url="http://127.0.0.1"),
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
            AISettings(provider="openai", base_url="http://127.0.0.1"),  # no api_key
        )
        with pytest.raises(AIAuthenticationError):
            adapter.chat([{"role": "user", "content": "hi"}])


class TestHealth:
    def test_available_when_provider_responds(self) -> None:
        adapter = _extended_adapter(
            transport_from(lambda r: _openai_text_response("OK")),
            AISettings(provider="openai", api_key=SecretStr("k"), base_url="http://127.0.0.1"),
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
            AISettings(provider="openai", base_url="http://127.0.0.1"),  # no api_key
        )
        result = adapter.health()

        assert result["available"] is False
        assert result["provider"] == "openai"
        assert "error" in result


class TestAuditRequestBestEffort:
    """Phase 12 (bandit B110): _audit_request()'s except block used to be a
    bare `except Exception: pass` - a genuine audit-write failure vanished
    with zero trace. Now logs a warning instead of silently swallowing it."""

    def test_audit_failure_is_logged_not_silently_swallowed(self, monkeypatch: pytest.MonkeyPatch) -> None:
        class _FailingAudit:
            def record(self, entry: object) -> None:
                raise RuntimeError("audit sink unreachable")

        adapter = _extended_adapter(
            transport_from(lambda r: _openai_text_response("OK")),
            AISettings(provider="openai", api_key=SecretStr("k"), base_url="http://127.0.0.1"),
        )
        adapter_with_audit = ExtendedAIAdapter(adapter._adapter, audit=_FailingAudit())

        calls: list[str] = []

        class _RecordingLogger:
            def warning(self, msg: str, *args: object) -> None:
                calls.append(msg % args if args else msg)

        monkeypatch.setattr(extended_adapter_module, "_logger", _RecordingLogger())

        # _audit_request() itself must not raise - the failure is contained.
        adapter_with_audit._audit_request("openai", "gpt-4", "generate")

        assert len(calls) == 1
        assert "audit" in calls[0].lower()
        assert "audit sink unreachable" in calls[0]

    def test_no_audit_configured_is_a_silent_no_op(self) -> None:
        """Unchanged behavior: when no audit publisher was wired at all
        (the common case, per __init__'s audit: Any = None default), there
        is nothing to fail, so no log line is expected either."""
        adapter = _extended_adapter(
            transport_from(lambda r: _openai_text_response("OK")),
            AISettings(provider="openai", api_key=SecretStr("k"), base_url="http://127.0.0.1"),
        )
        adapter._audit_request("openai", "gpt-4", "generate")  # must not raise


def _db_backed_extended_adapter(transport: httpx.MockTransport, base_url: str) -> ExtendedAIAdapter:
    """A DB-sourced (request-supplied-origin) base_url, reached via
    ExtendedAIAdapter's own generate()/chat() call sites - a distinct wiring
    point from AIProviderAdapter._enrich(), even though both delegate to the
    same _validate_base_url()."""
    encryption = FernetEncryptionService(Fernet.generate_key())
    record = AIProviderConfigRecord(
        provider="openai",
        api_key_encrypted=encryption.encrypt("sk-the-real-provider-key"),
        model="gpt-4",
        base_url=base_url,
        updated_at="2026-01-01T00:00:00Z",
    )
    client = AIClient(timeout=5, retry_count=0, retry_delay=0, transport=transport)
    resolver = AIConfigResolver(AISettings(), _DbConfigRepository(record), encryption)
    inner = AIProviderAdapter(
        settings=AISettings(),
        config_resolver=resolver,
        client=client,
        url_validator=SSRFURLValidator(),
    )
    return ExtendedAIAdapter(inner)


class TestGenerateAndChatBaseUrlSSRFProtection:
    """Phase 14 Sec 3.1: proves generate()'s and chat()'s own call sites
    invoke base_url validation - not inferred from AIProviderAdapter's
    coverage, since ExtendedAIAdapter reaches into the inner adapter's
    resolver/client directly rather than sharing _enrich()."""

    def test_generate_blocks_a_saved_private_base_url(self) -> None:
        hit = {"called": False}
        adapter = _db_backed_extended_adapter(
            transport_from(lambda r: _mark_and_respond(r, hit)), "http://127.0.0.1:9/v1"
        )
        with pytest.raises(AIUnsafeURLError):
            adapter.generate("system", "user")
        assert hit["called"] is False

    def test_chat_blocks_a_saved_private_base_url(self) -> None:
        hit = {"called": False}
        adapter = _db_backed_extended_adapter(
            transport_from(lambda r: _mark_and_respond(r, hit)), "http://127.0.0.1:9/v1"
        )
        with pytest.raises(AIUnsafeURLError):
            adapter.chat([{"role": "user", "content": "hi"}])
        assert hit["called"] is False

    def test_health_degrades_gracefully_instead_of_crashing(self) -> None:
        """health() calls generate() internally and catches Exception - a
        blocked base_url must degrade to unavailable, not propagate."""
        adapter = _db_backed_extended_adapter(
            transport_from(lambda r: _openai_text_response("unused")), "http://127.0.0.1:9/v1"
        )
        result = adapter.health()
        assert result["available"] is False
        assert "error" in result


def _mark_and_respond(request: httpx.Request, hit: dict) -> httpx.Response:
    hit["called"] = True
    return _openai_text_response("unused")
