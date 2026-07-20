"""Retrieve and decrypt a stored secret."""

from __future__ import annotations

from datetime import UTC, datetime

from kingsec.application.ports.outbound.encryption_service import EncryptionServicePort
from kingsec.application.ports.outbound.secret_provider import SecretProviderPort
from kingsec.domain.secret import SecretMetadata, SecretType

from .secret_dto import RetrieveSecretRequest, RetrieveSecretResponse


class RetrieveSecret:
    def __init__(
        self,
        encryption_service: EncryptionServicePort,
        secret_provider: SecretProviderPort,
    ) -> None:
        self._encryption_service = encryption_service
        self._secret_provider = secret_provider

    def execute(self, request: RetrieveSecretRequest) -> RetrieveSecretResponse:
        stored = self._secret_provider.get(request.name)
        if stored is None:
            from kingsec.application.errors import ApplicationError
            raise ApplicationError(f"secret '{request.name}' not found")

        ciphertext = bytes.fromhex(stored)
        plaintext = self._encryption_service.decrypt(ciphertext)

        masked = self._mask_value(plaintext)
        now = datetime.now(UTC).isoformat()
        metadata = SecretMetadata(
            name=request.name,
            secret_type=SecretType.DATABASE_PASSWORD,
            version=1,
            created_at=now,
            updated_at=now,
            masked_value=masked,
        )
        return RetrieveSecretResponse(plaintext=plaintext, metadata=metadata)

    @staticmethod
    def _mask_value(value: str) -> str:
        if not value:
            return ""
        if len(value) <= 8:
            return "*" * len(value)
        return value[:4] + "*" * (len(value) - 8) + value[-4:]
