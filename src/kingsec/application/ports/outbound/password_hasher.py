"""Port for password hashing — application layer contract.

The ``PasswordHasher`` port defines how the application hashes and verifies
passwords. Infrastructure implements this port with Argon2 (preferred) or
bcrypt; the application never imports cryptographic libraries.

Design decisions:
    - hash: one-way hash of a plaintext password.
    - verify: constant-time comparison of plaintext against a hash.
    - The port is technology-agnostic; the infrastructure decides the algorithm.
"""

from __future__ import annotations

from abc import ABC, abstractmethod


class PasswordHasher(ABC):
    """Abstract port for password hashing."""

    @abstractmethod
    def hash(self, password: str) -> str:
        """Hash a plaintext password.

        Args:
            password: The plaintext password to hash.

        Returns:
            The hashed password string.
        """

    @abstractmethod
    def verify(self, password: str, password_hash: str) -> bool:
        """Verify a plaintext password against a hash.

        Uses constant-time comparison to prevent timing attacks.

        Args:
            password: The plaintext password to check.
            password_hash: The stored hash to compare against.

        Returns:
            True if the password matches the hash.
        """
