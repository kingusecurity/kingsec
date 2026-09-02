"""Tests for HmacApiKeyHasher - KSEC-90-02.

Phase 90's JWT/API-key lifecycle audit found this class had zero direct
unit tests anywhere in the repository (only exercised indirectly through
``register_api_key_auth()`` in test_provisioning.py, which tests
provisioning's own placeholder guard, not the hasher's hashing/pepper/
verification/timing-safe-comparison behavior itself). These tests close
that gap directly against the real class - no mocks, no fakes.

All pepper/key values below are synthetic test-only strings, never a real
secret.
"""

from __future__ import annotations

import pytest

from kingsec.infrastructure.auth.api_key_hasher import HmacApiKeyHasher


class TestHmacApiKeyHasher:
    def test_hash_is_deterministic_for_the_same_pepper_and_key(self) -> None:
        hasher = HmacApiKeyHasher(pepper="test-pepper-" + "a" * 32)
        assert hasher.hash("ks_test_key_1") == hasher.hash("ks_test_key_1")

    def test_different_keys_under_the_same_pepper_hash_differently(self) -> None:
        hasher = HmacApiKeyHasher(pepper="test-pepper-" + "a" * 32)
        assert hasher.hash("ks_test_key_1") != hasher.hash("ks_test_key_2")

    def test_the_same_key_under_different_peppers_hashes_differently(self) -> None:
        """KSEC-90-02: proves the pepper genuinely participates in the
        hash, not just the key - this is the exact property the rotation
        runbook's §2.2 relies on to explain why rotating the pepper
        invalidates every previously-issued key."""
        hasher_a = HmacApiKeyHasher(pepper="test-pepper-" + "a" * 32)
        hasher_b = HmacApiKeyHasher(pepper="test-pepper-" + "b" * 32)
        assert hasher_a.hash("ks_test_key_1") != hasher_b.hash("ks_test_key_1")

    def test_verify_accepts_the_correct_key(self) -> None:
        hasher = HmacApiKeyHasher(pepper="test-pepper-" + "a" * 32)
        key_hash = hasher.hash("ks_test_key_1")
        assert hasher.verify("ks_test_key_1", key_hash) is True

    def test_verify_rejects_an_incorrect_key(self) -> None:
        hasher = HmacApiKeyHasher(pepper="test-pepper-" + "a" * 32)
        key_hash = hasher.hash("ks_test_key_1")
        assert hasher.verify("ks_wrong_key", key_hash) is False

    def test_verify_rejects_a_correct_key_hashed_under_a_different_pepper(self) -> None:
        """The exact "rotation invalidates existing keys" property the
        runbook describes, proven directly against the real hasher: a key
        hash produced under the OLD pepper must fail verification once
        the hasher is reconstructed with a NEW pepper - simulating what
        happens across a real pepper rotation without touching any real
        secret."""
        old_hasher = HmacApiKeyHasher(pepper="old-test-pepper-" + "a" * 32)
        key_hash = old_hasher.hash("ks_test_key_1")

        new_hasher = HmacApiKeyHasher(pepper="new-test-pepper-" + "b" * 32)
        assert new_hasher.verify("ks_test_key_1", key_hash) is False

    def test_empty_pepper_is_rejected_at_construction(self) -> None:
        """HmacApiKeyHasher itself refuses to be built with an empty
        pepper - this is the defense provisioning.py's own placeholder/
        empty check (already covered in test_provisioning.py) ultimately
        relies on; this test proves the hasher enforces it independently,
        not only its one caller."""
        with pytest.raises(ValueError, match="must not be empty"):
            HmacApiKeyHasher(pepper="")

    def test_hash_never_returns_the_plaintext_key(self) -> None:
        """KSEC-90-02 plaintext-storage-avoidance check: the hash output
        must never simply echo or embed the plaintext key."""
        hasher = HmacApiKeyHasher(pepper="test-pepper-" + "a" * 32)
        plaintext = "ks_super_secret_plaintext_value"
        key_hash = hasher.hash(plaintext)
        assert plaintext not in key_hash
