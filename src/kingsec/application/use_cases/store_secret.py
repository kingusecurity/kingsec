"""Store an encrypted secret."""

from __future__ import annotations

from datetime import UTC, datetime

from kingsec.application.ports.outbound.encryption_service import EncryptionServicePort
from kingsec.application.ports.outbound.secret_provider import SecretProviderPort
from kingsec.domain.secret import SecretMetadata, SecretType

from .secret_dto import StoreSecretRequest, StoreSecretResponse


class StoreSecret:
    def __init__(
        self,
        encryption_service: EncryptionServicePort,
        secret_provider: SecretProviderPort,
    ) -> None:
        self._encryption_service = encryption_service
        self._secret_provider = secret_provider

    def execute(self, request: StoreSecretRequest) -> StoreSecretResponse:
        ciphertext = self._encryption_service.encrypt(request.plaintext)
        self._secret_provider.set(request.name, ciphertext.hex())

        now = datetime.now(UTC).isoformat()
        try:
            secret_type = SecretType(request.secret_type)
        except ValueError:
            secret_type = (
                SecretType(request.secret_type)
                if request.secret_type in SecretType._value2member_map_
                else SecretType.DATABASE_PASSWORD
            )

        masked = self._mask_value(request.plaintext)
        metadata = SecretMetadata(
            name=request.name,
            secret_type=secret_type,
            version=1,
            created_at=now,
            updated_at=now,
            masked_value=masked,
        )
        return StoreSecretResponse(metadata=metadata)

    @staticmethod
    def _mask_value(value: str) -> str:
        if not value:
            return ""
        if len(value) <= 8:
            return "*" * len(value)
        return value[:4] + "*" * (len(value) - 8) + value[-4:]
