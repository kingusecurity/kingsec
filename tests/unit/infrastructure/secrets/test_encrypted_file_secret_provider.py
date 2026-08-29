"""Phase 24 — regression coverage for the secret-rotation corruption defect.

Phase 23's deployment-viability investigation reproduced a production
defect and characterized it as "``EncryptedFileSecretProvider.get()``
returns ciphertext instead of decrypting it." Tracing the complete call
chain (this phase's own required step) found the actual root cause one
layer deeper and in the opposite method: ``SecretProviderPort.get()``/
``set()`` are, by the established contract every real caller already
uses (``StoreSecret``, ``RetrieveSecret``, and two independent pre-existing
test files' own hand-written mock providers - none of which encrypt
anything themselves), meant to store and return **opaque strings
verbatim** - encryption is the *caller's* responsibility, not the
provider's.

``EncryptedFileSecretProvider.set()`` broke that contract by encrypting
internally - meaning ``StoreSecret`` (which already encrypts before
calling ``set()``) was **double-encrypting every secret it ever stored,
independent of rotation ever running.** ``get()`` was already correct
(returns the stored string verbatim). ``RotateSecrets`` compounded this by
treating whatever ``get()`` returned as plaintext and feeding it straight
back into the (encrypting) ``set()``, triple-wrapping data that was
already double-wrapped the moment it was first stored.

Confirmed empirically, this phase, against unmodified code, before
touching anything: a bare ``StoreSecret`` → ``RetrieveSecret`` round trip
(no rotation involved at all) already returned corrupted data.

The fix makes the provider genuinely "dumb" (matching its actual,
already-relied-upon contract) and moves ``RotateSecrets``'s own
encrypt/decrypt logic to mirror ``StoreSecret``/``RetrieveSecret``'s
existing, correct pattern - decrypt everything under the old key first
(a clean abort point if anything fails), rotate once, then re-encrypt and
write back everything under the new key.

All storage in this file is an isolated temp file per test (via
``tmp_path``) - never the developer's real KingSec secret store.
"""

from __future__ import annotations

import binascii

import pytest
from cryptography.fernet import Fernet, InvalidToken

from kingsec.application.use_cases.retrieve_secret import RetrieveSecret
from kingsec.application.use_cases.rotate_secrets import RotateSecrets
from kingsec.application.use_cases.secret_dto import RetrieveSecretRequest, RotateSecretsRequest, StoreSecretRequest
from kingsec.application.use_cases.store_secret import StoreSecret
from kingsec.infrastructure.secrets.encrypted_file_secret_provider import (
    EncryptedFileSecretProvider,
)
from kingsec.infrastructure.secrets.fernet_encryption_service import FernetEncryptionService


@pytest.fixture
def encryption_service() -> FernetEncryptionService:
    return FernetEncryptionService(Fernet.generate_key())


@pytest.fixture
def provider(encryption_service, tmp_path):
    return EncryptedFileSecretProvider(encryption_service, tmp_path / "secrets.json")


class TestProviderIsDumb:
    """The provider itself stores and returns opaque strings verbatim -
    it does not encrypt or decrypt. Confirmed directly, isolated from any
    use case, since this is the contract the whole fix depends on."""

    def test_set_then_get_returns_the_value_unchanged(self, provider) -> None:
        provider.set("k", "whatever-string-is-given")
        assert provider.get("k") == "whatever-string-is-given"

    def test_get_of_a_missing_secret_returns_none(self, provider) -> None:
        assert provider.get("does-not-exist") is None


class TestStoreThenRetrieve:
    """Scenarios 1-3: store a plaintext secret via the real StoreSecret use
    case, read it back via the real RetrieveSecret use case, and confirm
    the value that reaches the caller is genuine plaintext - not the
    corrupted, doubly-wrapped ciphertext the unmodified code produced.
    This does not involve rotation at all: the original defect corrupted
    data on the very first store, before rotation was ever invoked."""

    def test_stored_secret_is_readable_as_the_original_plaintext(
        self, encryption_service, provider
    ) -> None:
        StoreSecret(encryption_service, provider).execute(
            StoreSecretRequest(name="db_pass", plaintext="s3cret!")
        )
        result = RetrieveSecret(encryption_service, provider).execute(
            RetrieveSecretRequest(name="db_pass")
        )
        assert result.plaintext == "s3cret!"

    def test_the_providers_own_stored_representation_is_ciphertext_not_plaintext(
        self, encryption_service, provider
    ) -> None:
        """StoreSecret is the one that encrypts (once) before calling
        set() - the provider's own storage must reflect exactly that one
        layer of encryption, not zero (unencrypted) and not two
        (double-encrypted, the original defect)."""
        StoreSecret(encryption_service, provider).execute(
            StoreSecretRequest(name="db_pass", plaintext="s3cret!")
        )
        raw_on_disk = provider.get("db_pass")
        assert raw_on_disk != "s3cret!"
        ciphertext = binascii.unhexlify(raw_on_disk)
        # Exactly one layer: decrypting once recovers the real plaintext.
        assert encryption_service.decrypt(ciphertext) == "s3cret!"


class TestRotationPreservesPlaintext:
    """Scenarios 4-7: execute the real rotation path, confirm the plaintext
    survives, and confirm the stored representation is genuinely
    re-encrypted under the new key - not merely still-readable because the
    old key happens to be retained."""

    def test_secret_unchanged_after_rotation_via_the_real_rotate_secrets_use_case(
        self, encryption_service, provider
    ) -> None:
        StoreSecret(encryption_service, provider).execute(
            StoreSecretRequest(name="db_pass", plaintext="s3cret!")
        )

        result = RotateSecrets(encryption_service, provider).execute(RotateSecretsRequest())
        assert result.reencrypted_count == 1

        retrieved = RetrieveSecret(encryption_service, provider).execute(
            RetrieveSecretRequest(name="db_pass")
        )
        assert retrieved.plaintext == "s3cret!"

    def test_rotation_genuinely_re_encrypts_under_the_new_key(self, tmp_path) -> None:
        """The OLD key alone, without the new one, must no longer be able
        to decrypt the post-rotation ciphertext."""
        old_key = Fernet.generate_key()
        service = FernetEncryptionService(old_key)
        local_provider = EncryptedFileSecretProvider(service, tmp_path / "secrets.json")
        StoreSecret(service, local_provider).execute(
            StoreSecretRequest(name="s", plaintext="plaintext-value")
        )

        RotateSecrets(service, local_provider).execute(RotateSecretsRequest())

        ciphertext_after = binascii.unhexlify(local_provider.get("s"))
        with pytest.raises(InvalidToken):
            Fernet(old_key).decrypt(ciphertext_after)
        assert service.decrypt(ciphertext_after) == "plaintext-value"

    def test_stored_representation_remains_single_layer_ciphertext_after_rotation(
        self, encryption_service, provider
    ) -> None:
        """Confirms rotation doesn't add a spurious extra layer of
        encryption - exactly one decrypt recovers the plaintext, both
        before and after rotation."""
        StoreSecret(encryption_service, provider).execute(
            StoreSecretRequest(name="db_pass", plaintext="s3cret!")
        )
        RotateSecrets(encryption_service, provider).execute(RotateSecretsRequest())

        raw_on_disk = provider.get("db_pass")
        assert raw_on_disk != "s3cret!"
        ciphertext = binascii.unhexlify(raw_on_disk)
        assert encryption_service.decrypt(ciphertext) == "s3cret!"


class TestMultipleSecrets:
    """Scenario 8: rotation must handle more than one stored secret correctly."""

    def test_multiple_secrets_all_survive_rotation_unchanged(self, encryption_service, provider) -> None:
        for name, value in [("secret-a", "value-a"), ("secret-b", "value-b"), ("secret-c", "value-c")]:
            StoreSecret(encryption_service, provider).execute(StoreSecretRequest(name=name, plaintext=value))

        result = RotateSecrets(encryption_service, provider).execute(RotateSecretsRequest())
        assert result.reencrypted_count == 3

        for name, value in [("secret-a", "value-a"), ("secret-b", "value-b"), ("secret-c", "value-c")]:
            retrieved = RetrieveSecret(encryption_service, provider).execute(RetrieveSecretRequest(name=name))
            assert retrieved.plaintext == value


class TestEmptySecretStorage:
    """Scenario 9: rotation with nothing stored must not fail."""

    def test_rotation_with_no_secrets_stored_succeeds_with_zero_count(self, encryption_service, provider) -> None:
        result = RotateSecrets(encryption_service, provider).execute(RotateSecretsRequest())
        assert result.reencrypted_count == 0
        assert provider.list() == []


class TestCorruptedCiphertext:
    """Scenario 10: a corrupted stored value must fail loudly during
    rotation, not silently return/store the wrong value - propagating an
    exception here is the fail-safe outcome."""

    def test_invalid_hex_during_rotation_raises(self, provider, encryption_service) -> None:
        provider.set("api-key", "not-valid-hex-###")
        with pytest.raises(binascii.Error):
            RotateSecrets(encryption_service, provider).execute(RotateSecretsRequest())

    def test_valid_hex_but_invalid_ciphertext_during_rotation_raises(self, provider, encryption_service) -> None:
        provider.set("api-key", binascii.hexlify(b"not-a-real-fernet-token-at-all!!").decode())
        with pytest.raises(InvalidToken):
            RotateSecrets(encryption_service, provider).execute(RotateSecretsRequest())

    def test_rotation_does_not_mutate_anything_when_a_secret_fails_to_decrypt(
        self, provider, encryption_service
    ) -> None:
        """Confirms the fail-safe property precisely: decryption of every
        secret happens in a first pass, entirely before rotate_key() is
        called - so a corrupted secret aborts before the key (or any
        stored value) has changed at all."""
        StoreSecret(encryption_service, provider).execute(
            StoreSecretRequest(name="good", plaintext="fine")
        )
        provider.set("bad", "not-valid-hex-###")

        good_before = provider.get("good")
        with pytest.raises(binascii.Error):
            RotateSecrets(encryption_service, provider).execute(RotateSecretsRequest())

        assert provider.get("good") == good_before  # untouched
        retrieved = RetrieveSecret(encryption_service, provider).execute(RetrieveSecretRequest(name="good"))
        assert retrieved.plaintext == "fine"  # still decryptable under the still-unrotated key


class TestRestartBehavior:
    """Scenario 12: application restart / read-after-rotation, tested to
    the extent this architecture actually permits (see the final report's
    Limitations section for what it does not)."""

    def test_a_second_provider_instance_sharing_the_same_rotated_encryption_service_reads_correctly(
        self, encryption_service, provider, tmp_path
    ) -> None:
        """Simulates a fresh provider object constructed against the same
        file, while the same encryption-service instance (with both keys)
        is reused - the realistic 'restart within one process's lifetime'
        case this architecture supports."""
        StoreSecret(encryption_service, provider).execute(
            StoreSecretRequest(name="api-key", plaintext="sk-real-secret-value")
        )
        RotateSecrets(encryption_service, provider).execute(RotateSecretsRequest())

        reloaded = EncryptedFileSecretProvider(encryption_service, tmp_path / "secrets.json")
        result = RetrieveSecret(encryption_service, reloaded).execute(RetrieveSecretRequest(name="api-key"))
        assert result.plaintext == "sk-real-secret-value"

    def test_a_brand_new_encryption_service_built_from_only_the_original_key_cannot_read_rotated_data(
        self, tmp_path
    ) -> None:
        """Documents the real, current architectural limitation (see the
        Phase 24 report): the rotated key is never persisted anywhere a
        fresh process's Settings-driven construction would find it, so a
        genuine process restart - which rebuilds FernetEncryptionService
        from only the original KINGSEC_SECRETS__ENCRYPTION_KEY - loses
        access to anything rotated in a prior run. This is not new
        breakage from this fix; it is a pre-existing architectural gap
        that a correctness fix to the rotation logic itself does not
        (and per this phase's own scope, should not) also solve."""
        original_key = Fernet.generate_key()
        service = FernetEncryptionService(original_key)
        local_provider = EncryptedFileSecretProvider(service, tmp_path / "secrets.json")
        StoreSecret(service, local_provider).execute(
            StoreSecretRequest(name="api-key", plaintext="sk-real-secret-value")
        )
        RotateSecrets(service, local_provider).execute(RotateSecretsRequest())

        fresh_service = FernetEncryptionService(original_key)
        fresh_provider = EncryptedFileSecretProvider(fresh_service, tmp_path / "secrets.json")
        with pytest.raises(InvalidToken):
            RetrieveSecret(fresh_service, fresh_provider).execute(RetrieveSecretRequest(name="api-key"))


class TestRotationFailureBehavior:
    """Scenario 11: if rotation fails partway (a secret-provider write
    failure during the re-encryption pass, after the key has already
    rotated), the exception must propagate, and secrets already written
    back under the new key - as well as any not yet reached - must remain
    decryptable, since the encryption service retains prior keys."""

    def test_a_failing_secret_provider_during_the_write_back_pass_propagates_the_exception(
        self, encryption_service
    ) -> None:
        class _FailsOnSecondSet:
            def __init__(self) -> None:
                self._data: dict[str, str] = {}
                self._calls = 0

            def list(self):
                return list(self._data.keys())

            def get(self, name):
                return self._data.get(name)

            def set(self, name, value):
                self._calls += 1
                if self._calls == 2:
                    raise OSError("disk write failed")
                self._data[name] = value

            def exists(self, name):
                return name in self._data

            def delete(self, name):
                self._data.pop(name, None)

        failing_provider = _FailsOnSecondSet()
        StoreSecret(encryption_service, failing_provider).execute(
            StoreSecretRequest(name="secret-a", plaintext="value-a")
        )
        failing_provider._calls = 0  # each setup store also calls set() - reset before the next one
        StoreSecret(encryption_service, failing_provider).execute(
            StoreSecretRequest(name="secret-b", plaintext="value-b")
        )
        # Reset again so the injected failure happens inside rotation's own
        # write-back pass, not the StoreSecret setup calls above.
        failing_provider._calls = 0

        with pytest.raises(OSError, match="disk write failed"):
            RotateSecrets(encryption_service, failing_provider).execute(RotateSecretsRequest())

    def test_secrets_written_before_a_mid_rotation_failure_remain_decryptable(
        self, encryption_service, provider
    ) -> None:
        StoreSecret(encryption_service, provider).execute(
            StoreSecretRequest(name="secret-a", plaintext="value-a")
        )
        StoreSecret(encryption_service, provider).execute(
            StoreSecretRequest(name="secret-b", plaintext="value-b")
        )

        real_set = provider.set
        calls = {"n": 0}

        def _flaky_set(name, value):
            calls["n"] += 1
            if calls["n"] == 2:
                raise OSError("simulated disk failure")
            real_set(name, value)

        provider.set = _flaky_set  # type: ignore[method-assign]
        with pytest.raises(OSError):
            RotateSecrets(encryption_service, provider).execute(RotateSecretsRequest())
        provider.set = real_set  # type: ignore[method-assign]

        # Whichever secret was re-encrypted before the failure, and
        # whichever was not, must both still be readable - the encryption
        # service retains the old key for exactly this transition window.
        for name, value in [("secret-a", "value-a"), ("secret-b", "value-b")]:
            retrieved = RetrieveSecret(encryption_service, provider).execute(RetrieveSecretRequest(name=name))
            assert retrieved.plaintext == value
