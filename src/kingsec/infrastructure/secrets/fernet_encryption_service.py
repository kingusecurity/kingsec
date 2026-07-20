"""Fernet-based encryption service — uses cryptography.fernet.

This is the ONLY module in KingSec that imports cryptography.
"""

from __future__ import annotations

from cryptography.fernet import Fernet, MultiFernet

from kingsec.application.ports.outbound.encryption_service import EncryptionServicePort


class FernetEncryptionService(EncryptionServicePort):
    def __init__(self, key: bytes) -> None:
        if not key:
            raise ValueError("Fernet encryption key must not be empty")
        self._keys: list[bytes] = [key]
        self._fernet = MultiFernet([Fernet(k) for k in self._keys])

    def encrypt(self, plaintext: str) -> bytes:
        return self._fernet.encrypt(plaintext.encode("utf-8"))

    def decrypt(self, ciphertext: bytes) -> str:
        return self._fernet.decrypt(ciphertext).decode("utf-8")

    def rotate_key(self) -> None:
        new_key = Fernet.generate_key()
        self._keys.insert(0, new_key)
        self._fernet = MultiFernet([Fernet(k) for k in self._keys])

    def can_decrypt(self, ciphertext: bytes) -> bool:
        try:
            self._fernet.decrypt(ciphertext)
            return True
        except Exception:
            return False
