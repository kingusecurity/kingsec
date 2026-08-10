"""Resolves the effective AI provider configuration on every call.

DB-saved settings (via ``AIProviderConfigRepository``) override the env-var
``AISettings`` when a row exists. This is the mechanism that makes a save
from the Settings UI take effect immediately, with no process restart: an
``AIProviderAdapter`` holding this resolver re-reads the current DB row on
every call instead of a fixed value captured once at composition time.

Scope stays exactly what the design specified: provider, API key, model,
base_url come from here. Tuning knobs (temperature, max_tokens, retry
count/delay, verify_ssl) stay env-only - callers keep reading those
directly off the injected ``AISettings``, unrelated to this resolver.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import TYPE_CHECKING

from kingsec.application.ports.outbound.ai_provider_config_repository import (
    AIProviderConfigRecord,
    AIProviderConfigRepository,
)
from kingsec.application.ports.outbound.encryption_service import EncryptionServicePort
from kingsec.infrastructure.logging import get_logger

from .providers import ProviderConfig, default_model_for, resolve_provider

if TYPE_CHECKING:  # typing only; no runtime import of config internals
    from kingsec.infrastructure.config.models import AISettings

_logger = get_logger("kingsec.infrastructure.ai")


@dataclass(frozen=True)
class ResolvedAIConfig:
    """The effective provider/key/model/base_url for one AI call."""

    provider: ProviderConfig
    api_key: str | None
    model: str
    base_url: str | None
    source: str  # "database" | "environment" | "none"


class AIConfigResolver:
    """Resolves DB-first, env-fallback AI configuration, fresh per call."""

    def __init__(
        self,
        env_settings: AISettings,
        config_repo: AIProviderConfigRepository,
        encryption: EncryptionServicePort,
    ) -> None:
        self._env_settings = env_settings
        self._config_repo = config_repo
        self._encryption = encryption

    def resolve(self) -> ResolvedAIConfig:
        """Return the configuration to use for the AI call happening now."""
        record = self._config_repo.get()
        if record is not None:
            return self._from_db_record(record)
        return self._from_env()

    def _from_db_record(self, record: AIProviderConfigRecord) -> ResolvedAIConfig:
        api_key: str | None = None
        if record.api_key_encrypted is not None:
            try:
                api_key = self._encryption.decrypt(record.api_key_encrypted)
            except Exception:
                # Ciphertext that no longer decrypts (e.g. the encryption
                # key rotated) must degrade to "no key configured", never
                # raise and break every AI call in the meantime.
                _logger.warning("failed to decrypt saved AI provider key")
                api_key = None
        return ResolvedAIConfig(
            provider=resolve_provider(record.provider),
            api_key=api_key,
            # A blank model must default to something that provider
            # actually has, not the env AISettings default (an Anthropic
            # model name) - that mismatch is exactly what produced a real
            # 404 against Gemini (confirmed against Gemini's real API:
            # an unrecognised model returns 404, distinct from the 400 a
            # bad key returns).
            model=record.model or default_model_for(record.provider),
            base_url=record.base_url,
            source="database",
        )

    def _from_env(self) -> ResolvedAIConfig:
        env_key = self._env_settings.api_key
        provider_name = self._env_settings.provider
        model = self._env_settings.model
        # Same mismatch, env-var path: AISettings.model's own pydantic
        # default is an Anthropic model name. If it's still sitting at
        # that untouched default while the configured provider is
        # something else, nobody deliberately chose it - use that
        # provider's own default instead of a model it doesn't have.
        if model == default_model_for("anthropic") and provider_name.strip().lower() not in ("anthropic", "claude"):
            model = default_model_for(provider_name)
        return ResolvedAIConfig(
            provider=resolve_provider(provider_name),
            api_key=env_key.get_secret_value() if env_key is not None else None,
            model=model,
            base_url=self._env_settings.base_url,
            source="environment" if env_key is not None else "none",
        )
