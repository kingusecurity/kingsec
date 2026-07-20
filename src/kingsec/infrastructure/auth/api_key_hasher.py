"""HMAC-SHA256 API key hasher — infrastructure implementation.

API keys are high-entropy random strings, so we use HMAC-SHA256 with a
configurable server-side pepper rather than a slow KDF (which is appropriate
for user passwords but unnecessary here). The pepper is loaded from settings,
never hardcoded.
"""

from __future__ import annotations

import hashlib
import hmac

from kingsec.application.ports import ApiKeyHasher


class HmacApiKeyHasher(ApiKeyHasher):
    """Hash API keys using HMAC-SHA256 with a server-side pepper."""

    def __init__(self, pepper: str) -> None:
        if not pepper:
            raise ValueError("API key pepper must not be empty")
        self._pepper = pepper.encode("utf-8")

    def hash(self, plaintext_key: str) -> str:
        return hmac.new(
            self._pepper,
            plaintext_key.encode("utf-8"),
            hashlib.sha256,
        ).hexdigest()

    def verify(self, plaintext_key: str, key_hash: str) -> bool:
        expected = self.hash(plaintext_key)
        return hmac.compare_digest(expected, key_hash)
