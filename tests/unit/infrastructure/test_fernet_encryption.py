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

    def test_with_custom_key(self) -> None:
        key = Fernet.generate_key()
        svc = FernetEncryptionService(key=key)
        ciphertext = svc.encrypt("custom-key-test")
        assert svc.decrypt(ciphertext) == "custom-key-test"

    def test_no_rotate_key_method_exists(self) -> None:
        """Phase 57 / Finding E-01: rotate_key() was removed entirely — an
        in-process, unpersisted key-generation operation could never
        survive a restart. Key material now comes only from construction
        arguments (see the legacy_keys tests below)."""
        svc = FernetEncryptionService(key=_KEY)
        assert not hasattr(svc, "rotate_key")


class TestFernetEncryptionServiceLegacyKeys:
    """Phase 57 / Finding E-01: a primary key plus ordered, decrypt-only
    legacy keys — durable, operator-configured multi-key support, as
    opposed to the removed in-memory-only rotate_key()."""

    def test_new_encryption_always_uses_the_primary_key(self) -> None:
        primary = Fernet.generate_key()
        legacy = Fernet.generate_key()
        svc = FernetEncryptionService(key=primary, legacy_keys=[legacy])
        ciphertext = svc.encrypt("value")

        primary_only = FernetEncryptionService(key=primary)
        assert primary_only.decrypt(ciphertext) == "value"

        legacy_only = FernetEncryptionService(key=legacy)
        assert not legacy_only.can_decrypt(ciphertext)

    def test_legacy_key_can_still_decrypt_data_encrypted_under_it(self) -> None:
        old_primary = Fernet.generate_key()
        new_primary = Fernet.generate_key()

        old_service = FernetEncryptionService(key=old_primary)
        ciphertext_from_before_rotation = old_service.encrypt("value")

        # Simulates the post-rotation configuration: old_primary demoted
        # to a legacy (decrypt-only) key, new_primary promoted to primary.
        rotated_service = FernetEncryptionService(key=new_primary, legacy_keys=[old_primary])
        assert rotated_service.decrypt(ciphertext_from_before_rotation) == "value"

    def test_multiple_legacy_keys_are_all_honored(self) -> None:
        key_a = Fernet.generate_key()
        key_b = Fernet.generate_key()
        key_c = Fernet.generate_key()

        ciphertext_a = FernetEncryptionService(key=key_a).encrypt("from-a")
        ciphertext_b = FernetEncryptionService(key=key_b).encrypt("from-b")

        service = FernetEncryptionService(key=key_c, legacy_keys=[key_b, key_a])
        assert service.decrypt(ciphertext_a) == "from-a"
        assert service.decrypt(ciphertext_b) == "from-b"

    def test_no_legacy_keys_behaves_identically_to_before_this_fix(self) -> None:
        """Backward compatibility: an unrotated deployment (no legacy keys
        configured) must behave byte-for-byte as it always has."""
        svc = FernetEncryptionService(key=_KEY)
        ciphertext = svc.encrypt("unrotated")
        assert svc.decrypt(ciphertext) == "unrotated"
        assert svc.can_decrypt(ciphertext)
