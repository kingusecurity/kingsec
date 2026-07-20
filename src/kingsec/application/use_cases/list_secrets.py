"""List all stored secret metadata (no plaintext)."""

from __future__ import annotations

from datetime import UTC, datetime

from kingsec.application.ports.outbound.secret_provider import SecretProviderPort
from kingsec.domain.secret import SecretMetadata, SecretType

from .secret_dto import ListSecretsRequest, ListSecretsResponse


class ListSecrets:
    def __init__(self, secret_provider: SecretProviderPort) -> None:
        self._secret_provider = secret_provider

    def execute(self, request: ListSecretsRequest) -> ListSecretsResponse:
        names = self._secret_provider.list()
        secrets: list[SecretMetadata] = []
        now = datetime.now(UTC).isoformat()

        for name in names:
            stored = self._secret_provider.get(name)
            if stored is not None:
                masked = self._mask_value(stored)
            else:
                masked = "****"
            metadata = SecretMetadata(
                name=name,
                secret_type=SecretType.DATABASE_PASSWORD,
                version=1,
                created_at=now,
                updated_at=now,
                masked_value=masked,
            )
            secrets.append(metadata)

        return ListSecretsResponse(secrets=secrets)

    @staticmethod
    def _mask_value(value: str) -> str:
        if not value:
            return ""
        if len(value) <= 8:
            return "*" * len(value)
        return value[:4] + "*" * (len(value) - 8) + value[-4:]
