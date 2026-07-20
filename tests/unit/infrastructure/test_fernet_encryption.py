"""Tests for FernetEncryptionService."""

from __future__ import annotations

from cryptography.fernet import Fernet

from kingsec.infrastructure.secrets.fernet_encryption_service import (
    FernetEncryptionService,
)


_KEY = Fernet.generate_key()


class TestFernetEncryptionService:
    def test_encrypt_decrypt(self) -> None:
        svc = FernetEncryptionService(key=_KEY)
        ciphertext = svc.encrypt("hello world")
        plaintext = svc.decrypt(ciphertext)
        assert plaintext == "hello world"

    def test_encrypt_different_each_time(self) -> None:
        svc = FernetEncryptionService(key=_KEY)
        c1 = svc.encrypt("same")
        c2 = svc.encrypt("same")
        assert c1 != c2

    def test_can_decrypt_valid(self) -> None:
        svc = FernetEncryptionService(key=_KEY)
        ciphertext = svc.encrypt("test")
        assert svc.can_decrypt(ciphertext)

    def test_can_decrypt_invalid(self) -> None:
        svc = FernetEncryptionService(key=_KEY)
        assert not svc.can_decrypt(b"invalid-data")

    def test_rotate_key(self) -> None:
        svc = FernetEncryptionService(key=_KEY)
        c1 = svc.encrypt("before-rotate")
        svc.rotate_key()
        assert svc.decrypt(c1) == "before-rotate"
        c2 = svc.encrypt("after-rotate")
        assert svc.decrypt(c2) == "after-rotate"

    def test_with_custom_key(self) -> None:
        key = Fernet.generate_key()
        svc = FernetEncryptionService(key=key)
        ciphertext = svc.encrypt("custom-key-test")
        assert svc.decrypt(ciphertext) == "custom-key-test"
