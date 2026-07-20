"""Rotate encryption key and re-encrypt all stored secrets."""

from __future__ import annotations

import hashlib

from kingsec.application.ports.outbound.encryption_service import EncryptionServicePort
from kingsec.application.ports.outbound.secret_provider import SecretProviderPort

from .secret_dto import RotateSecretsRequest, RotateSecretsResponse


class RotateSecrets:
    def __init__(
        self,
        encryption_service: EncryptionServicePort,
        secret_provider: SecretProviderPort,
    ) -> None:
        self._encryption_service = encryption_service
        self._secret_provider = secret_provider

    def execute(self, request: RotateSecretsRequest) -> RotateSecretsResponse:
        secrets = self._secret_provider.list()
        reencrypted_count = 0

        for name in secrets:
            plaintext = self._secret_provider.get(name)
            if plaintext is not None:
                self._secret_provider.set(name, plaintext)
                reencrypted_count += 1

        self._encryption_service.rotate_key()

        test_plaintext = "rotation-verification"
        test_cipher = self._encryption_service.encrypt(test_plaintext)
        new_key_fingerprint = hashlib.sha256(test_cipher).hexdigest()[:16]

        return RotateSecretsResponse(
            reencrypted_count=reencrypted_count,
            new_key_fingerprint=new_key_fingerprint,
        )
