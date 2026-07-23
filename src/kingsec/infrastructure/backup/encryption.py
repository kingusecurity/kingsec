from __future__ import annotations

from cryptography.fernet import Fernet

from kingsec.application.ports.outbound import BackupEncryptionPort


class AESBackupEncryptionService(BackupEncryptionPort):
    def __init__(self, key: bytes | None = None) -> None:
        if key:
            self._key = key
        else:
            self._key = Fernet.generate_key()
        self._fernet = Fernet(self._key)

    def encrypt(self, data: bytes) -> bytes:
        return self._fernet.encrypt(data)

    def decrypt(self, data: bytes) -> bytes:
        return self._fernet.decrypt(data)

    @property
    def key(self) -> bytes:
        return self._key
