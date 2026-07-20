"""Validate configuration — check required secrets exist and encryption is active."""

from __future__ import annotations

from kingsec.application.ports.outbound.encryption_service import EncryptionServicePort
from kingsec.application.ports.outbound.secret_provider import SecretProviderPort

from .secret_dto import ValidateConfigurationRequest, ValidateConfigurationResponse


class ValidateConfiguration:
    def __init__(
        self,
        encryption_service: EncryptionServicePort,
        secret_provider: SecretProviderPort,
    ) -> None:
        self._encryption_service = encryption_service
        self._secret_provider = secret_provider

    def execute(self, request: ValidateConfigurationRequest) -> ValidateConfigurationResponse:
        missing: list[str] = []
        for secret_name in request.required_secrets:
            if not self._secret_provider.exists(secret_name):
                missing.append(secret_name)

        encryption_enabled = True
        try:
            test_val = self._encryption_service.encrypt("health-check")
            can_decrypt = self._encryption_service.can_decrypt(test_val)
            encryption_enabled = can_decrypt
        except Exception:
            encryption_enabled = False

        provider_type = type(self._secret_provider).__name__

        return ValidateConfigurationResponse(
            valid=len(missing) == 0 and encryption_enabled,
            missing_secrets=missing,
            encryption_enabled=encryption_enabled,
            provider_type=provider_type,
        )
