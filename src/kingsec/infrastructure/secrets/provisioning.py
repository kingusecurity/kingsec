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
    """Register the encryption service and secret provider on the container.

    Raises:
        ConfigError: If ``KINGSEC_SECRETS__ENCRYPTION_KEY`` is unset, empty,
            or not valid Fernet key material (wrong length, not base64,
            etc). ``FernetEncryptionService``/``Fernet`` already reject all
            of these with a bare ``ValueError`` naming neither the
            environment variable nor a fix (Phase 26 - confirmed by direct
            testing); this re-raises as ``ConfigError`` in the same style as
            every other secret-related startup error in this codebase,
            without changing which values are accepted or rejected.
    """
    encryption_key_setting = settings.secrets.encryption_key
    if encryption_key_setting is None:
        raise ConfigError(
            "KINGSEC_SECRETS__ENCRYPTION_KEY is not set. "
            'Generate one with: python -c "from cryptography.fernet import Fernet; print(Fernet.generate_key().decode())"'
        )
    encryption_key = encryption_key_setting.get_secret_value().encode("utf-8")
    try:
        encryption_service = FernetEncryptionService(encryption_key)
    except ValueError as exc:
        raise ConfigError(
            "KINGSEC_SECRETS__ENCRYPTION_KEY is not valid Fernet key material "
            f"({exc}). "
            'Generate one with: python -c "from cryptography.fernet import Fernet; print(Fernet.generate_key().decode())"'
        ) from exc
    secret_provider = EncryptedFileSecretProvider(encryption_service, secrets_file_path)

    container.register_instance(EncryptionServicePort, encryption_service)
    container.register_instance(SecretProviderPort, secret_provider)
