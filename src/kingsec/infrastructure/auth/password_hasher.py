"""Argon2 password hasher — infrastructure implementation.

Uses argon2-cffi for password hashing, which is the recommended algorithm
for new applications (OWASP, PHC winner). Falls back to bcrypt if argon2
is not available.

Security considerations:
    - Uses argon2id (hybrid of argon2i and argon2d) for resistance to both
      side-channel and GPU-based attacks.
    - Parameters: time_cost=3, memory_cost=65536 (64MB), parallelism=4.
    - Hashes are encoded with algorithm parameters for future-proofing.
"""

from __future__ import annotations

import hashlib
import hmac
import importlib.util
import secrets
from base64 import b64decode, b64encode

from kingsec.application.ports import PasswordHasher


class Argon2PasswordHasher(PasswordHasher):
    """Password hasher using argon2id (preferred) or fallback to PBKDF2-SHA256.

    If argon2-cffi is not installed, falls back to PBKDF2-SHA256 with
    random salts and high iteration count. This maintains security without
    requiring optional dependencies.
    """

    def __init__(self) -> None:
        self._use_argon2 = self._check_argon2_available()

    @staticmethod
    def _check_argon2_available() -> bool:
        """Check if argon2-cffi is available."""
        return importlib.util.find_spec("argon2") is not None

    def hash(self, password: str) -> str:
        """Hash a password using argon2id or PBKDF2-SHA256."""
        if self._use_argon2:
            return self._hash_argon2(password)
        return self._hash_pbkdf2(password)

    def verify(self, password: str, password_hash: str) -> bool:
        """Verify a password against a hash."""
        if password_hash.startswith("$argon2"):
            return self._verify_argon2(password, password_hash)
        if password_hash.startswith("pbkdf2:"):
            return self._verify_pbkdf2(password, password_hash)
        # Unknown format
        return False

    def _hash_argon2(self, password: str) -> str:
        """Hash using argon2id."""
        from argon2 import PasswordHasher as Argon2Hasher
        from argon2 import Type as Argon2Type

        hasher = Argon2Hasher(
            time_cost=3,
            memory_cost=65536,  # 64 MB
            parallelism=4,
            hash_len=32,
            salt_len=16,
            type=Argon2Type.ID,
        )
        return hasher.hash(password)

    def _verify_argon2(self, password: str, password_hash: str) -> bool:
        """Verify against argon2id hash."""
        from argon2 import PasswordHasher as Argon2Hasher
        from argon2 import Type as Argon2Type
        from argon2.exceptions import InvalidHashError, VerifyMismatchError

        hasher = Argon2Hasher(
            time_cost=3,
            memory_cost=65536,
            parallelism=4,
            hash_len=32,
            salt_len=16,
            type=Argon2Type.ID,
        )
        try:
            hasher.verify(password_hash, password)
            return True
        except (VerifyMismatchError, InvalidHashError):
            return False

    def _hash_pbkdf2(self, password: str) -> str:
        """Hash using PBKDF2-SHA256 (fallback)."""
        salt = secrets.token_bytes(32)
        iterations = 600000  # OWASP recommendation
        dk = hashlib.pbkdf2_hmac("sha256", password.encode(), salt, iterations)
        salt_b64 = b64encode(salt).decode()
        dk_b64 = b64encode(dk).decode()
        return f"pbkdf2:sha256:{iterations}:{salt_b64}:{dk_b64}"

    def _verify_pbkdf2(self, password: str, password_hash: str) -> bool:
        """Verify against PBKDF2-SHA256 hash."""
        try:
            parts = password_hash.split(":")
            if len(parts) != 5:
                return False
            iterations = int(parts[2])
            salt = b64decode(parts[3])
            stored_hash = b64decode(parts[4])
            dk = hashlib.pbkdf2_hmac("sha256", password.encode(), salt, iterations)
            return hmac.compare_digest(dk, stored_hash)
        except (ValueError, IndexError):
            return False
