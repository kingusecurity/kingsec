"""Decrypt a ciphertext using the encryption service."""

from __future__ import annotations

from kingsec.application.ports.outbound.encryption_service import EncryptionServicePort

from .secret_dto import DecryptSecretRequest, DecryptSecretResponse


class DecryptSecret:
    def __init__(self, encryption_service: EncryptionServicePort) -> None:
        self._encryption_service = encryption_service

    def execute(self, request: DecryptSecretRequest) -> DecryptSecretResponse:
        plaintext = self._encryption_service.decrypt(request.ciphertext)
        return DecryptSecretResponse(plaintext=plaintext)
