from __future__ import annotations

from kingsec.infrastructure.backup.encryption import AESBackupEncryptionService


class TestAESBackupEncryptionService:
    def test_encrypt_decrypt(self) -> None:
        svc = AESBackupEncryptionService()
        original = b"sensitive backup data"
        encrypted = svc.encrypt(original)
        assert encrypted != original
        decrypted = svc.decrypt(encrypted)
        assert decrypted == original

    def test_with_custom_key(self) -> None:
        from cryptography.fernet import Fernet
        key = Fernet.generate_key()
        svc = AESBackupEncryptionService(key=key)
        original = b"test data"
        encrypted = svc.encrypt(original)
        decrypted = svc.decrypt(encrypted)
        assert decrypted == original
