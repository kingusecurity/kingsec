from __future__ import annotations

from abc import ABC, abstractmethod


class BackupEncryptionPort(ABC):
    @abstractmethod
    def encrypt(self, data: bytes) -> bytes:
        ...

    @abstractmethod
    def decrypt(self, data: bytes) -> bytes:
        ...
