"""Unit tests for AIConfigResolver: DB-first, env-fallback resolution."""

from __future__ import annotations

from datetime import UTC, datetime

import pytest
from cryptography.fernet import Fernet
from pydantic import SecretStr

from kingsec.application.ports.outbound.ai_provider_config_repository import (
    AIProviderConfigRecord,
    AIProviderConfigRepository,
)
from kingsec.infrastructure.ai.config_resolver import AIConfigResolver
from kingsec.infrastructure.ai.errors import AIError
from kingsec.infrastructure.config.models import AISettings
from kingsec.infrastructure.secrets.fernet_encryption_service import FernetEncryptionService


class _InMemoryConfigRepository(AIProviderConfigRepository):
    def __init__(self, record: AIProviderConfigRecord | None = None) -> None:
        self._record = record

    def get(self) -> AIProviderConfigRecord | None:
        return self._record

    def save(self, record: AIProviderConfigRecord) -> None:
        self._record = record


def _encryption() -> FernetEncryptionService:
    return FernetEncryptionService(Fernet.generate_key())


class TestNoDatabaseRecord:
    def test_falls_back_to_env_settings_with_key(self) -> None:
        env_settings = AISettings(provider="anthropic", api_key=SecretStr("env-key"), model="claude-x")
        resolver = AIConfigResolver(env_settings, _InMemoryConfigRepository(None), _encryption())

        resolved = resolver.resolve()

        assert resolved.source == "environment"
        assert resolved.api_key == "env-key"
        assert resolved.model == "claude-x"
        assert resolved.provider.name == "anthropic"

    def test_no_env_key_either_means_source_none(self) -> None:
        env_settings = AISettings(provider="anthropic", api_key=None)
        resolver = AIConfigResolver(env_settings, _InMemoryConfigRepository(None), _encryption())

        resolved = resolver.resolve()

        assert resolved.source == "none"
        assert resolved.api_key is None

    def test_untouched_default_model_is_replaced_for_a_non_anthropic_env_provider(self) -> None:
        """KINGSEC_AI__PROVIDER=gemini with no KINGSEC_AI__MODEL set left
        AISettings.model at its pydantic default ("claude-sonnet-4-5", an
        Anthropic model) - sending that to Gemini's real API produces a
        genuine 404 (confirmed directly against the real endpoint: an
        unrecognised model returns 404, distinct from the 400 a bad key
        returns). Must use Gemini's own default instead."""
        env_settings = AISettings(provider="gemini", api_key=SecretStr("env-key"))
        resolver = AIConfigResolver(env_settings, _InMemoryConfigRepository(None), _encryption())

        assert resolver.resolve().model == "gemini-1.5-flash"

    def test_deliberately_set_model_for_a_non_anthropic_provider_is_kept(self) -> None:
        """If the operator genuinely configured a model for their chosen
        provider, that must never be overridden."""
        env_settings = AISettings(provider="gemini", api_key=SecretStr("env-key"), model="gemini-2.0-flash")
        resolver = AIConfigResolver(env_settings, _InMemoryConfigRepository(None), _encryption())

        assert resolver.resolve().model == "gemini-2.0-flash"


class TestDatabaseRecordPresent:
    def test_database_record_overrides_env(self) -> None:
        env_settings = AISettings(provider="anthropic", api_key=SecretStr("env-key"), model="claude-env")
        encryption = _encryption()
        ciphertext = encryption.encrypt("db-key")
        record = AIProviderConfigRecord(
            provider="openai",
            api_key_encrypted=ciphertext,
            model="gpt-db",
            base_url="https://custom.example.com",
            updated_at=datetime.now(UTC).isoformat(),
        )
        resolver = AIConfigResolver(env_settings, _InMemoryConfigRepository(record), encryption)

        resolved = resolver.resolve()

        assert resolved.source == "database"
        assert resolved.provider.name == "openai"
        assert resolved.api_key == "db-key"
        assert resolved.model == "gpt-db"
        assert resolved.base_url == "https://custom.example.com"

    def test_database_record_without_model_falls_back_to_its_own_providers_default(self) -> None:
        """A blank model on a DB record must default to something its OWN
        provider actually has, never the env's model for a possibly
        different provider - that mismatch is exactly what produced a
        real 404 against Gemini (env default is an Anthropic model name)."""
        env_settings = AISettings(provider="anthropic", model="claude-env")
        encryption = _encryption()
        record = AIProviderConfigRecord(
            provider="gemini",
            api_key_encrypted=encryption.encrypt("db-key"),
            model=None,
            base_url=None,
            updated_at=datetime.now(UTC).isoformat(),
        )
        resolver = AIConfigResolver(env_settings, _InMemoryConfigRepository(record), encryption)

        assert resolver.resolve().model == "gemini-1.5-flash"

    def test_database_record_without_model_and_same_provider_as_env(self) -> None:
        """When the DB record's provider matches the env's, the provider
        default and the env's configured model may legitimately differ -
        the provider default (not the env's arbitrary value) wins, since
        the DB record's own provider is what's authoritative here."""
        env_settings = AISettings(provider="anthropic", model="claude-env")
        encryption = _encryption()
        record = AIProviderConfigRecord(
            provider="anthropic",
            api_key_encrypted=encryption.encrypt("db-key"),
            model=None,
            base_url=None,
            updated_at=datetime.now(UTC).isoformat(),
        )
        resolver = AIConfigResolver(env_settings, _InMemoryConfigRepository(record), encryption)

        assert resolver.resolve().model == "claude-sonnet-4-5"

    def test_database_record_with_no_key_means_no_api_key(self) -> None:
        env_settings = AISettings(provider="anthropic", api_key=SecretStr("env-key"))
        record = AIProviderConfigRecord(
            provider="anthropic", api_key_encrypted=None, model=None, base_url=None, updated_at="x"
        )
        resolver = AIConfigResolver(env_settings, _InMemoryConfigRepository(record), _encryption())

        resolved = resolver.resolve()

        assert resolved.source == "database"
        assert resolved.api_key is None

    def test_undecryptable_ciphertext_degrades_to_no_key_not_raise(self) -> None:
        """Wrong encryption key (e.g. rotated) must not break every AI call -
        degrade to "no key", same as if none were configured."""
        env_settings = AISettings(provider="anthropic", api_key=SecretStr("env-key"))
        wrong_key_ciphertext = FernetEncryptionService(Fernet.generate_key()).encrypt("db-key")
        record = AIProviderConfigRecord(
            provider="anthropic",
            api_key_encrypted=wrong_key_ciphertext,
            model=None,
            base_url=None,
            updated_at="x",
        )
        # A different encryption service instance (different key) than the
        # one that produced the ciphertext above.
        resolver = AIConfigResolver(env_settings, _InMemoryConfigRepository(record), _encryption())

        resolved = resolver.resolve()

        assert resolved.api_key is None
        assert resolved.source == "database"

    def test_unknown_provider_in_database_raises_ai_error(self) -> None:
        """A bad provider name saved somehow (should never happen given
        save-time validation) fails loudly via the existing AIError path
        rather than silently using the wrong provider."""
        env_settings = AISettings(provider="anthropic")
        record = AIProviderConfigRecord(
            provider="not-a-real-provider", api_key_encrypted=None, model=None, base_url=None, updated_at="x"
        )
        resolver = AIConfigResolver(env_settings, _InMemoryConfigRepository(record), _encryption())

        with pytest.raises(AIError):
            resolver.resolve()
