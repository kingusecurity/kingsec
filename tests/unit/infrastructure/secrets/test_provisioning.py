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
