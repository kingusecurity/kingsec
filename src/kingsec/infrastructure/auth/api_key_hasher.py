"""HMAC-SHA256 API key hasher — infrastructure implementation.

API keys are high-entropy random strings, so we use HMAC-SHA256 with a static
pepper rather than a slow KDF (which is appropriate for user passwords but
unnecessary here). The pepper provides server-side secret protection.
"""

from __future__ import annotations

import hashlib
import hmac

from kingsec.application.ports import ApiKeyHasher

# In production this should come from configuration/secret store.
_PEPPER = b"kingsec-api-key-pepper-v1"


class HmacApiKeyHasher(ApiKeyHasher):
    """Hash API keys using HMAC-SHA256 with a server-side pepper."""

    def hash(self, plaintext_key: str) -> str:
        return hmac.new(
            _PEPPER,
            plaintext_key.encode("utf-8"),
            hashlib.sha256,
        ).hexdigest()

    def verify(self, plaintext_key: str, key_hash: str) -> bool:
        expected = self.hash(plaintext_key)
        return hmac.compare_digest(expected, key_hash)
