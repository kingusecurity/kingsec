"""Port for API key hashing — application layer contract.

API keys require a different hashing strategy than user passwords:
    - API keys are high-entropy random strings (no need for slow hashes).
    - SHA-256 HMAC (with a static pepper) is sufficient and fast.
    - The plaintext key is shown once at creation and never stored.
"""

from __future__ import annotations

from abc import ABC, abstractmethod


class ApiKeyHasher(ABC):
    """Abstract port for hashing API keys."""

    @abstractmethod
    def hash(self, plaintext_key: str) -> str:
        """Hash a plaintext API key for storage.

        Args:
            plaintext_key: The raw API key string.

        Returns:
            A deterministic hash string for storage.
        """

    @abstractmethod
    def verify(self, plaintext_key: str, key_hash: str) -> bool:
        """Verify a plaintext API key against a stored hash.

        Args:
            plaintext_key: The raw API key string to check.
            key_hash: The stored hash to compare against.

        Returns:
            True if the key matches the hash.
        """
