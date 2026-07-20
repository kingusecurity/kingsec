"""Delete a stored secret."""

from __future__ import annotations

from kingsec.application.ports.outbound.secret_provider import SecretProviderPort

from .secret_dto import DeleteSecretRequest, DeleteSecretResponse


class DeleteSecret:
    def __init__(self, secret_provider: SecretProviderPort) -> None:
        self._secret_provider = secret_provider

    def execute(self, request: DeleteSecretRequest) -> DeleteSecretResponse:
        if not self._secret_provider.exists(request.name):
            return DeleteSecretResponse(success=False)
        self._secret_provider.delete(request.name)
        return DeleteSecretResponse(success=True)
