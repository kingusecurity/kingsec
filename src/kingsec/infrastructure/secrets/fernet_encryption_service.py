"""Fernet-based encryption service — uses cryptography.fernet.

This is the ONLY module in KingSec that imports cryptography.

Key material (a primary key plus zero or more ordered legacy decrypt-only
keys) comes entirely from the caller's construction arguments, which
``infrastructure.secrets.provisioning`` sources from durable configuration
(``SecretsSettings.encryption_key`` / ``legacy_encryption_keys``). This
service does not generate, persist, or otherwise mutate key material at
runtime (Phase 57 / Finding E-01) — every key any instance can encrypt or
decrypt with is one a fresh process, given the same configuration, would
also have. "Rotation" of the encryption key is therefore an operator
config change (set a new primary key, keep the old one as a legacy key)
followed by a restart, not an operation this class exposes.
"""

from __future__ import annotations

from collections.abc import Sequence

from cryptography.fernet import Fernet, MultiFernet

from kingsec.application.ports.outbound.encryption_service import EncryptionServicePort


class FernetEncryptionService(EncryptionServicePort):
    def __init__(self, key: bytes, legacy_keys: Sequence[bytes] | None = None) -> None:
        """Construct the service with a primary key and optional legacy keys.

        Args:
            key: The primary key. All new ``encrypt()`` calls use this key.
            legacy_keys: Additional keys, newest first, accepted for
                ``decrypt()``/``can_decrypt()`` only — never used to
                encrypt. Pass every key that any currently-stored
                ciphertext might still be encrypted under, so it remains
                decryptable after the primary key changes.
        """
        if not key:
            raise ValueError("Fernet encryption key must not be empty")
        self._keys: list[bytes] = [key, *(legacy_keys or [])]
        self._fernet = MultiFernet([Fernet(k) for k in self._keys])

    def encrypt(self, plaintext: str) -> bytes:
        return self._fernet.encrypt(plaintext.encode("utf-8"))

    def decrypt(self, ciphertext: bytes) -> str:
        return self._fernet.decrypt(ciphertext).decode("utf-8")

    def can_decrypt(self, ciphertext: bytes) -> bool:
        try:
            self._fernet.decrypt(ciphertext)
            return True
        except Exception:
            return False
