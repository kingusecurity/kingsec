"""Rotate encryption key and re-encrypt all stored secrets.

``SecretProviderPort.get()``/``set()`` store and return opaque strings
verbatim - they do not encrypt or decrypt anything (see
``EncryptedFileSecretProvider``'s own docstring). Encryption is this use
case's own responsibility, exactly as ``StoreSecret``/``RetrieveSecret``
already do it: decode the stored hex string to ciphertext bytes, decrypt.

Order matters, and is split into two passes rather than one interleaved
loop:

1. Decrypt every stored secret first, entirely under the *old* key. If any
   secret fails to decrypt, nothing has been mutated yet and nothing has
   been rotated - a clean, safe abort.
2. Only once every value is known-good plaintext does the key actually
   rotate, and only then are the secrets re-encrypted and written back -
   now genuinely under the *new* key, since ``encrypt()`` always uses the
   current (newest) key. Rotating before re-encrypting, or interleaving
   decrypt/re-encrypt per secret before rotating, would silently
   re-encrypt everything under the key that's about to become old.
"""

from __future__ import annotations

import binascii
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
        names = self._secret_provider.list()

        decrypted: dict[str, str] = {}
        for name in names:
            stored = self._secret_provider.get(name)
            if stored is not None:
                ciphertext = binascii.unhexlify(stored)
                decrypted[name] = self._encryption_service.decrypt(ciphertext)

        self._encryption_service.rotate_key()

        for name, plaintext in decrypted.items():
            new_ciphertext = self._encryption_service.encrypt(plaintext)
            self._secret_provider.set(name, new_ciphertext.hex())

        test_plaintext = "rotation-verification"
        test_cipher = self._encryption_service.encrypt(test_plaintext)
        new_key_fingerprint = hashlib.sha256(test_cipher).hexdigest()[:16]

        return RotateSecretsResponse(
            reencrypted_count=len(decrypted),
            new_key_fingerprint=new_key_fingerprint,
        )
