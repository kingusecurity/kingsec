"""DI wiring for secrets infrastructure."""

from __future__ import annotations

from typing import Any

from kingsec.application.ports.outbound.encryption_service import EncryptionServicePort
from kingsec.application.ports.outbound.secret_provider import SecretProviderPort
from kingsec.infrastructure.config.errors import ConfigError
from kingsec.infrastructure.config.settings import Settings

from .encrypted_file_secret_provider import EncryptedFileSecretProvider
from .fernet_encryption_service import FernetEncryptionService

_GENERATE_KEY_HINT = 'Generate one with: python -c "from cryptography.fernet import Fernet; print(Fernet.generate_key().decode())"'


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
        ConfigError: If any entry in ``KINGSEC_SECRETS__LEGACY_ENCRYPTION_KEYS``
            is not valid Fernet key material — validated individually so the
            error names the legacy list specifically, not the (valid)
            primary key (Phase 57 / Finding E-01).
    """
    encryption_key_setting = settings.secrets.encryption_key
    if encryption_key_setting is None:
        raise ConfigError(f"KINGSEC_SECRETS__ENCRYPTION_KEY is not set. {_GENERATE_KEY_HINT}")
    encryption_key = encryption_key_setting.get_secret_value().encode("utf-8")

    legacy_keys: list[bytes] = []
    for index, legacy_setting in enumerate(settings.secrets.legacy_encryption_keys):
        legacy_key = legacy_setting.get_secret_value().encode("utf-8")
        try:
            FernetEncryptionService(legacy_key)
        except ValueError as exc:
            raise ConfigError(
                f"KINGSEC_SECRETS__LEGACY_ENCRYPTION_KEYS[{index}] is not valid Fernet key material ({exc})."
            ) from exc
        legacy_keys.append(legacy_key)

    try:
        encryption_service = FernetEncryptionService(encryption_key, legacy_keys=legacy_keys)
    except ValueError as exc:
        raise ConfigError(
            f"KINGSEC_SECRETS__ENCRYPTION_KEY is not valid Fernet key material ({exc}). {_GENERATE_KEY_HINT}"
        ) from exc
    secret_provider = EncryptedFileSecretProvider(encryption_service, secrets_file_path)

    container.register_instance(EncryptionServicePort, encryption_service)
    container.register_instance(SecretProviderPort, secret_provider)
