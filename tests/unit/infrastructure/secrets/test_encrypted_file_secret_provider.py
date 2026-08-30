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
existing, correct pattern - decrypt everything first (a clean abort
point if anything fails), then re-encrypt and write back everything
under the current primary key.

Phase 57 / Finding E-01 further removed ``EncryptionServicePort.rotate_key()``
entirely: it generated a new key in process memory only, which was never
persisted anywhere a fresh process would find it, so a real restart after
calling it made every re-encrypted secret permanently undecryptable. Key
material now comes exclusively from durable configuration (a primary key
plus ordered legacy decrypt-only keys) - see ``TestRestartBehavior`` and
``TestFernetEncryptionServiceLegacyKeys`` (test_fernet_encryption.py) for
the regression coverage.

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
        """Phase 57 / Finding E-01: the "new key" now comes from durable
        configuration (the operator sets a new primary key and demotes
        the old one to legacy), not from an in-process rotate_key() call.
        After RotateSecrets runs against a service configured this way,
        the OLD key alone (without being listed as legacy) must no longer
        be able to decrypt the post-rotation ciphertext - it has genuinely
        moved onto the new primary key, not merely stayed valid because
        the old key was silently retained forever."""
        old_key = Fernet.generate_key()
        new_key = Fernet.generate_key()

        # Store under the old key, as if this happened before rotation.
        old_service = FernetEncryptionService(old_key)
        local_provider = EncryptedFileSecretProvider(old_service, tmp_path / "secrets.json")
        StoreSecret(old_service, local_provider).execute(
            StoreSecretRequest(name="s", plaintext="plaintext-value")
        )

        # Simulates the operator's actual rotation action: new primary key
        # configured, old key demoted to legacy (decrypt-only), restarted.
        rotated_service = FernetEncryptionService(new_key, legacy_keys=[old_key])
        rotated_provider = EncryptedFileSecretProvider(rotated_service, tmp_path / "secrets.json")
        RotateSecrets(rotated_service, rotated_provider).execute(RotateSecretsRequest())

        ciphertext_after = binascii.unhexlify(rotated_provider.get("s"))
        with pytest.raises(InvalidToken):
            Fernet(old_key).decrypt(ciphertext_after)
        assert Fernet(new_key).decrypt(ciphertext_after).decode("utf-8") == "plaintext-value"
        assert rotated_service.decrypt(ciphertext_after) == "plaintext-value"

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
    """Scenario 12: application restart / read-after-rotation.

    Phase 57 / Finding E-01 fixed the real gap here: previously, a
    genuine process restart after calling the rotation endpoint lost
    access to everything rotated in the prior run, because the "new key"
    was generated in-process and never persisted anywhere a fresh
    process's Settings-driven construction would find it. Key material
    now comes entirely from durable configuration (a primary key plus
    ordered legacy decrypt-only keys), so a fresh process's ability to
    decrypt depends only on that configuration, never on in-memory state
    from a process that no longer exists."""

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

    def test_a_fresh_process_with_unchanged_configuration_reads_correctly(self, tmp_path) -> None:
        """Phase 57 / Finding E-01 fix: a genuine process restart that
        rebuilds FernetEncryptionService from the SAME configured key
        (no rotation attempted at all) must always be able to read
        everything - this is the baseline restart-survivability case,
        and it was never broken (the defect was specific to the
        now-removed in-process rotate_key(), not to restarting per se)."""
        original_key = Fernet.generate_key()
        service = FernetEncryptionService(original_key)
        local_provider = EncryptedFileSecretProvider(service, tmp_path / "secrets.json")
        StoreSecret(service, local_provider).execute(
            StoreSecretRequest(name="api-key", plaintext="sk-real-secret-value")
        )

        # Simulate a restart: fresh service and provider from the same
        # configured key, no legacy keys involved.
        fresh_service = FernetEncryptionService(original_key)
        fresh_provider = EncryptedFileSecretProvider(fresh_service, tmp_path / "secrets.json")
        result = RetrieveSecret(fresh_service, fresh_provider).execute(RetrieveSecretRequest(name="api-key"))
        assert result.plaintext == "sk-real-secret-value"

    def test_a_fresh_process_configured_with_the_rotated_key_as_legacy_reads_correctly(
        self, tmp_path
    ) -> None:
        """Phase 57 / Finding E-01 — the actual fix under test: a genuine
        process restart configured per the documented rotation procedure
        (new primary key, old key moved to KINGSEC_SECRETS__LEGACY_ENCRYPTION_KEYS)
        must be able to decrypt data that a prior process encrypted under
        the old key, WITHOUT that prior process ever having called
        RotateSecrets. This is restart survivability (R2): the fresh
        process's ability to decrypt depends only on its own durable
        configuration, never on in-memory state from a process that no
        longer exists."""
        old_key = Fernet.generate_key()
        new_key = Fernet.generate_key()

        old_service = FernetEncryptionService(old_key)
        old_provider = EncryptedFileSecretProvider(old_service, tmp_path / "secrets.json")
        StoreSecret(old_service, old_provider).execute(
            StoreSecretRequest(name="api-key", plaintext="sk-real-secret-value")
        )

        # Simulate the restart with the new operator-driven configuration.
        fresh_service = FernetEncryptionService(new_key, legacy_keys=[old_key])
        fresh_provider = EncryptedFileSecretProvider(fresh_service, tmp_path / "secrets.json")
        result = RetrieveSecret(fresh_service, fresh_provider).execute(RetrieveSecretRequest(name="api-key"))
        assert result.plaintext == "sk-real-secret-value"

    def test_a_fresh_process_missing_the_legacy_key_fails_loudly_not_silently(self, tmp_path) -> None:
        """R8 - failure must be explicit: if an operator sets a new
        primary key but forgets to carry the old key forward as a legacy
        key, decryption of existing secrets must raise, never silently
        return wrong data or an empty value."""
        old_key = Fernet.generate_key()
        new_key = Fernet.generate_key()

        old_service = FernetEncryptionService(old_key)
        old_provider = EncryptedFileSecretProvider(old_service, tmp_path / "secrets.json")
        StoreSecret(old_service, old_provider).execute(
            StoreSecretRequest(name="api-key", plaintext="sk-real-secret-value")
        )

        # Operator error: forgot to list old_key as a legacy key.
        misconfigured_service = FernetEncryptionService(new_key)
        misconfigured_provider = EncryptedFileSecretProvider(misconfigured_service, tmp_path / "secrets.json")
        with pytest.raises(InvalidToken):
            RetrieveSecret(misconfigured_service, misconfigured_provider).execute(
                RetrieveSecretRequest(name="api-key")
            )

    def test_rotate_secrets_use_case_migrates_ciphertext_across_a_restart(self, tmp_path) -> None:
        """End-to-end fixed flow: store under the old key: restart with
        new primary + old as legacy (R2); call RotateSecrets to migrate
        the on-disk ciphertext onto the new primary key (R1 - the "new
        key" was already durable configuration before this call, not
        something generated by this call); confirm a THIRD fresh process,
        configured with ONLY the new key and no legacy keys at all, can
        still read it — proving the migration is genuinely complete and
        the old key is no longer needed."""
        old_key = Fernet.generate_key()
        new_key = Fernet.generate_key()

        old_service = FernetEncryptionService(old_key)
        old_provider = EncryptedFileSecretProvider(old_service, tmp_path / "secrets.json")
        StoreSecret(old_service, old_provider).execute(
            StoreSecretRequest(name="api-key", plaintext="sk-real-secret-value")
        )

        service = FernetEncryptionService(new_key, legacy_keys=[old_key])
        local_provider = EncryptedFileSecretProvider(service, tmp_path / "secrets.json")
        RotateSecrets(service, local_provider).execute(RotateSecretsRequest())

        # A third, independent process configured with ONLY the new key -
        # no legacy keys at all - must still be able to read it, proving
        # the migration genuinely moved the ciphertext, not merely that
        # the old key happened to still be configured.
        new_key_only_service = FernetEncryptionService(new_key)
        new_key_only_provider = EncryptedFileSecretProvider(new_key_only_service, tmp_path / "secrets.json")
        result = RetrieveSecret(new_key_only_service, new_key_only_provider).execute(
            RetrieveSecretRequest(name="api-key")
        )
        assert result.plaintext == "sk-real-secret-value"


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
