"""Port for the admin-configured AI provider settings store.

A thin, single-row settings record — no domain entity/lifecycle needed,
consistent with how ``LicenseRepository`` treats similar "one active
configuration" state. ``api_key_encrypted`` is opaque ciphertext to this
port: encryption/decryption is the caller's responsibility (via
``EncryptionServicePort``), keeping this port free of crypto concerns.
"""

from __future__ import annotations

from abc import ABC, abstractmethod
from dataclasses import dataclass


@dataclass(frozen=True)
class AIProviderConfigRecord:
    provider: str
    api_key_encrypted: bytes | None
    model: str | None
    base_url: str | None
    updated_at: str


class AIProviderConfigRepository(ABC):
    """Persists the single active AI provider configuration, if any."""

    @abstractmethod
    def get(self) -> AIProviderConfigRecord | None:
        """Return the saved configuration, or None if never configured."""

    @abstractmethod
    def save(self, record: AIProviderConfigRecord) -> None:
        """Create or replace the single configuration row."""
