"""Port for encryption operations — no infrastructure imports."""

from __future__ import annotations

from abc import ABC, abstractmethod


class EncryptionServicePort(ABC):
    @abstractmethod
    def encrypt(self, plaintext: str) -> bytes: ...

    @abstractmethod
    def decrypt(self, ciphertext: bytes) -> str: ...

    @abstractmethod
    def rotate_key(self) -> None: ...

    @abstractmethod
    def can_decrypt(self, ciphertext: bytes) -> bool: ...
