"""Encrypt a plaintext value using the encryption service."""

from __future__ import annotations

from kingsec.application.ports.outbound.encryption_service import EncryptionServicePort

from .secret_dto import EncryptSecretRequest, EncryptSecretResponse


class EncryptSecret:
    def __init__(self, encryption_service: EncryptionServicePort) -> None:
        self._encryption_service = encryption_service

    def execute(self, request: EncryptSecretRequest) -> EncryptSecretResponse:
        ciphertext = self._encryption_service.encrypt(request.plaintext)
        return EncryptSecretResponse(ciphertext=ciphertext)
