"""Re-encrypt all stored secrets under the currently configured primary key.

``SecretProviderPort.get()``/``set()`` store and return opaque strings
verbatim - they do not encrypt or decrypt anything (see
``EncryptedFileSecretProvider``'s own docstring). Encryption is this use
case's own responsibility, exactly as ``StoreSecret``/``RetrieveSecret``
already do it: decode the stored hex string to ciphertext bytes, decrypt.

This use case does NOT generate a new encryption key itself (Phase 57 /
Finding E-01 removed that responsibility from ``EncryptionServicePort``
entirely). The encryption service's primary key comes from durable,
operator-managed configuration (``KINGSEC_SECRETS__ENCRYPTION_KEY`` plus
``KINGSEC_SECRETS__LEGACY_ENCRYPTION_KEYS``); the operator's actual
rotation action is to set a new primary key, keep the old one as a legacy
key, and restart. Calling this use case afterward migrates every
currently-stored secret from whatever key it happens to be encrypted
under to that new primary key.

Order still matters, and is still split into two passes rather than one
interleaved loop:

1. Decrypt every stored secret first, under whichever configured key
   (primary or legacy) each one happens to validate against. If any
   secret fails to decrypt under every configured key, nothing has been
   mutated yet - a clean, safe abort.
2. Only once every value is known-good plaintext are the secrets
   re-encrypted and written back - under the *current primary* key, since
   ``encrypt()`` always uses it. Re-encrypting per secret in a single pass
   (rather than decrypt-everything-first) would leave a partially-migrated
   store indistinguishable from a corrupted one if a later secret in the
   loop failed to decrypt.
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
