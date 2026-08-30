"""Phase 26: register_secrets() must reject invalid Fernet key material with
a clear ConfigError, not a bare ValueError.

``FernetEncryptionService``/``cryptography.fernet.Fernet`` already reject an
empty, malformed, or wrong-length ``KINGSEC_SECRETS__ENCRYPTION_KEY`` - fail-
closed behavior was never broken. But before this phase, that rejection
surfaced as a raw ``ValueError`` naming neither the environment variable nor
a fix (e.g. "Fernet key must be 32 url-safe base64-encoded bytes."),
inconsistent with every other secret-related startup error in this codebase
(the missing-key case already raised a proper ``ConfigError`` here; the
placeholder/empty checks in ``infrastructure.auth.provisioning`` do too).
These tests prove the upgraded error type/message without changing which
values are accepted or rejected.
"""

from __future__ import annotations

from typing import Any

import pytest
from cryptography.fernet import Fernet
from pydantic import SecretStr

from kingsec.application.ports.outbound.encryption_service import EncryptionServicePort
from kingsec.infrastructure.config.errors import ConfigError
from kingsec.infrastructure.config.models import SecretsSettings
from kingsec.infrastructure.config.settings import Settings
from kingsec.infrastructure.secrets.provisioning import register_secrets


class _FakeContainer:
    def __init__(self) -> None:
        self.instances: dict[type[Any], Any] = {}

    def register_instance(self, service_type: type[Any], instance: Any) -> None:
        self.instances[service_type] = instance


def _settings_with_encryption_key(value: str | None) -> Settings:
    secrets = SecretsSettings(encryption_key=None if value is None else SecretStr(value))
    return Settings(secrets=secrets)


def _settings_with_legacy_keys(primary: str, legacy: list[str]) -> Settings:
    secrets = SecretsSettings(
        encryption_key=SecretStr(primary),
        legacy_encryption_keys=[SecretStr(k) for k in legacy],
    )
    return Settings(secrets=secrets)


class TestRegisterSecretsErrorQuality:
    def test_missing_key_raises_config_error(self, tmp_path: Any) -> None:
        settings = _settings_with_encryption_key(None)
        with pytest.raises(ConfigError) as excinfo:
            register_secrets(_FakeContainer(), settings, secrets_file_path=str(tmp_path / "secrets.json"))
        assert "KINGSEC_SECRETS__ENCRYPTION_KEY" in str(excinfo.value)

    def test_empty_key_raises_config_error_not_bare_value_error(self, tmp_path: Any) -> None:
        settings = _settings_with_encryption_key("")
        with pytest.raises(ConfigError) as excinfo:
            register_secrets(_FakeContainer(), settings, secrets_file_path=str(tmp_path / "secrets.json"))
        message = str(excinfo.value)
        assert "KINGSEC_SECRETS__ENCRYPTION_KEY" in message
        assert "Generate one with" in message

    def test_malformed_key_raises_config_error_not_bare_value_error(self, tmp_path: Any) -> None:
        settings = _settings_with_encryption_key("not-a-valid-fernet-key-at-all!!")
        with pytest.raises(ConfigError) as excinfo:
            register_secrets(_FakeContainer(), settings, secrets_file_path=str(tmp_path / "secrets.json"))
        message = str(excinfo.value)
        assert "KINGSEC_SECRETS__ENCRYPTION_KEY" in message
        assert "Generate one with" in message

    def test_wrong_length_key_raises_config_error(self, tmp_path: Any) -> None:
        settings = _settings_with_encryption_key("c2hvcnQ=")  # valid base64, wrong length
        with pytest.raises(ConfigError) as excinfo:
            register_secrets(_FakeContainer(), settings, secrets_file_path=str(tmp_path / "secrets.json"))
        assert "KINGSEC_SECRETS__ENCRYPTION_KEY" in str(excinfo.value)

    def test_valid_key_still_accepted(self, tmp_path: Any) -> None:
        settings = _settings_with_encryption_key(Fernet.generate_key().decode())
        container = _FakeContainer()
        register_secrets(container, settings, secrets_file_path=str(tmp_path / "secrets.json"))  # must not raise
        assert container.instances.get(EncryptionServicePort) is not None

    def test_error_never_contains_the_key_value(self, tmp_path: Any) -> None:
        bad_value = "not-a-valid-fernet-key-at-all!!"
        settings = _settings_with_encryption_key(bad_value)
        with pytest.raises(ConfigError) as excinfo:
            register_secrets(_FakeContainer(), settings, secrets_file_path=str(tmp_path / "secrets.json"))
        assert bad_value not in str(excinfo.value)


class TestRegisterSecretsLegacyKeys:
    """Phase 57 / Finding E-01: KINGSEC_SECRETS__LEGACY_ENCRYPTION_KEYS lets
    an operator carry a retired primary key forward as decrypt-only, so
    existing secrets survive a key change across a restart."""

    def test_no_legacy_keys_behaves_exactly_as_before(self, tmp_path: Any) -> None:
        settings = _settings_with_encryption_key(Fernet.generate_key().decode())
        container = _FakeContainer()
        register_secrets(container, settings, secrets_file_path=str(tmp_path / "secrets.json"))
        service = container.instances[EncryptionServicePort]
        ciphertext = service.encrypt("value")
        assert service.decrypt(ciphertext) == "value"

    def test_valid_legacy_key_is_accepted_and_can_decrypt(self, tmp_path: Any) -> None:
        old_key = Fernet.generate_key().decode()
        new_key = Fernet.generate_key().decode()
        settings = _settings_with_legacy_keys(primary=new_key, legacy=[old_key])
        container = _FakeContainer()
        register_secrets(container, settings, secrets_file_path=str(tmp_path / "secrets.json"))

        service = container.instances[EncryptionServicePort]
        # Ciphertext produced under the old key (simulating data stored
        # before this rotation) must still decrypt via the new service.
        old_service_ciphertext = Fernet(old_key.encode()).encrypt(b"legacy-value")
        assert service.decrypt(old_service_ciphertext) == "legacy-value"
        # New encryption must use the primary (new) key, not a legacy one.
        new_ciphertext = service.encrypt("fresh-value")
        assert Fernet(new_key.encode()).decrypt(new_ciphertext).decode() == "fresh-value"

    def test_malformed_legacy_key_raises_config_error_naming_the_legacy_list(self, tmp_path: Any) -> None:
        settings = _settings_with_legacy_keys(
            primary=Fernet.generate_key().decode(),
            legacy=["not-a-valid-fernet-key-at-all!!"],
        )
        with pytest.raises(ConfigError) as excinfo:
            register_secrets(_FakeContainer(), settings, secrets_file_path=str(tmp_path / "secrets.json"))
        message = str(excinfo.value)
        assert "KINGSEC_SECRETS__LEGACY_ENCRYPTION_KEYS" in message
        # Must not be misattributed to the (valid) primary key.
        assert "KINGSEC_SECRETS__ENCRYPTION_KEY is not valid" not in message

    def test_malformed_legacy_key_error_never_contains_the_key_value(self, tmp_path: Any) -> None:
        bad_value = "not-a-valid-fernet-key-at-all!!"
        settings = _settings_with_legacy_keys(primary=Fernet.generate_key().decode(), legacy=[bad_value])
        with pytest.raises(ConfigError) as excinfo:
            register_secrets(_FakeContainer(), settings, secrets_file_path=str(tmp_path / "secrets.json"))
        assert bad_value not in str(excinfo.value)

    def test_multiple_legacy_keys_all_validated_and_usable(self, tmp_path: Any) -> None:
        key_a = Fernet.generate_key().decode()
        key_b = Fernet.generate_key().decode()
        primary = Fernet.generate_key().decode()
        settings = _settings_with_legacy_keys(primary=primary, legacy=[key_a, key_b])
        container = _FakeContainer()
        register_secrets(container, settings, secrets_file_path=str(tmp_path / "secrets.json"))

        service = container.instances[EncryptionServicePort]
        ciphertext_a = Fernet(key_a.encode()).encrypt(b"from-a")
        ciphertext_b = Fernet(key_b.encode()).encrypt(b"from-b")
        assert service.decrypt(ciphertext_a) == "from-a"
        assert service.decrypt(ciphertext_b) == "from-b"
