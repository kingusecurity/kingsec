"""DI wiring for secrets infrastructure."""

from __future__ import annotations

from typing import Any

from kingsec.application.ports.outbound.encryption_service import EncryptionServicePort
from kingsec.application.ports.outbound.secret_provider import SecretProviderPort
from kingsec.infrastructure.config.errors import ConfigError
from kingsec.infrastructure.config.settings import Settings

from .encrypted_file_secret_provider import EncryptedFileSecretProvider
from .fernet_encryption_service import FernetEncryptionService


def register_secrets(container: Any, settings: Settings, secrets_file_path: str = "secrets.json") -> None:
    encryption_key_setting = settings.secrets.encryption_key
    if encryption_key_setting is None:
        raise ConfigError(
            "KINGSEC_SECRETS__ENCRYPTION_KEY is not set. "
            "Generate one with: python -c \"from cryptography.fernet import Fernet; print(Fernet.generate_key().decode())\""
        )
    encryption_key = encryption_key_setting.get_secret_value().encode("utf-8")
    encryption_service = FernetEncryptionService(encryption_key)
    secret_provider = EncryptedFileSecretProvider(encryption_service, secrets_file_path)

    container.register_instance(EncryptionServicePort, encryption_service)
    container.register_instance(SecretProviderPort, secret_provider)
