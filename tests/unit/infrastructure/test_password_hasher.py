"""Tests for password hasher infrastructure."""

from __future__ import annotations

import pytest

from kingsec.infrastructure.auth.password_hasher import Argon2PasswordHasher


class TestArgon2PasswordHasher:
    @pytest.fixture
    def hasher(self) -> Argon2PasswordHasher:
        return Argon2PasswordHasher()

    def test_hash_returns_string(self, hasher: Argon2PasswordHasher) -> None:
        result = hasher.hash("SecurePass123")
        assert isinstance(result, str)
        assert len(result) > 0

    def test_hash_is_deterministic_with_different_salts(self, hasher: Argon2PasswordHasher) -> None:
        h1 = hasher.hash("SecurePass123")
        h2 = hasher.hash("SecurePass123")
        # Same password should produce different hashes (random salt)
        assert h1 != h2

    def test_verify_correct_password(self, hasher: Argon2PasswordHasher) -> None:
        password = "SecurePass123"
        hashed = hasher.hash(password)
        assert hasher.verify(password, hashed) is True

    def test_verify_wrong_password(self, hasher: Argon2PasswordHasher) -> None:
        password = "SecurePass123"
        hashed = hasher.hash(password)
        assert hasher.verify("WrongPass123", hashed) is False

    def test_verify_empty_password(self, hasher: Argon2PasswordHasher) -> None:
        password = "SecurePass123"
        hashed = hasher.hash(password)
        assert hasher.verify("", hashed) is False

    def test_pbkdf2_fallback(self) -> None:
        """Test PBKDF2 fallback when argon2 is not available."""
        hasher = Argon2PasswordHasher()
        # Force PBKDF2 mode
        hasher._use_argon2 = False

        password = "SecurePass123"
        hashed = hasher.hash(password)
        assert hashed.startswith("pbkdf2:")
        assert hasher.verify(password, hashed) is True
        assert hasher.verify("WrongPass", hashed) is False

    def test_verify_unknown_format(self, hasher: Argon2PasswordHasher) -> None:
        assert hasher.verify("password", "unknown_format") is False
