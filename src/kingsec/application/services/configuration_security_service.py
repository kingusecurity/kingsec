"""Application service for configuration security — masks secrets, validates config.

No infrastructure imports. Only depends on ports.
"""

from __future__ import annotations

from kingsec.application.ports.outbound.encryption_service import EncryptionServicePort
from kingsec.application.ports.outbound.secret_provider import SecretProviderPort


class ConfigurationSecurityService:
    def __init__(
        self,
        encryption_service: EncryptionServicePort,
        secret_provider: SecretProviderPort,
    ) -> None:
        self._encryption_service = encryption_service
        self._secret_provider = secret_provider

    def mask_value(self, value: str) -> str:
        if not value:
            return ""
        if len(value) <= 8:
            return "*" * len(value)
        return value[:4] + "*" * (len(value) - 8) + value[-4:]

    def validate_configuration(self, required_secrets: list[str] | None = None) -> dict[str, object]:
        missing: list[str] = []
        for secret_name in (required_secrets or []):
            if not self._secret_provider.exists(secret_name):
                missing.append(secret_name)

        encryption_enabled = True
        try:
            test_val = self._encryption_service.encrypt("health-check")
            encryption_enabled = self._encryption_service.can_decrypt(test_val)
        except Exception:
            encryption_enabled = False

        return {
            "valid": len(missing) == 0 and encryption_enabled,
            "missing_secrets": missing,
            "encryption_enabled": encryption_enabled,
            "provider_type": type(self._secret_provider).__name__,
            "stored_secrets_count": len(self._secret_provider.list()),
        }

    def get_encryption_status(self) -> dict[str, object]:
        encryption_enabled = True
        try:
            test_val = self._encryption_service.encrypt("health-check")
            encryption_enabled = self._encryption_service.can_decrypt(test_val)
        except Exception:
            encryption_enabled = False

        return {
            "encryption_enabled": encryption_enabled,
            "provider_type": type(self._secret_provider).__name__,
            "stored_secrets_count": len(self._secret_provider.list()),
            "encryption_version": "1",
        }
