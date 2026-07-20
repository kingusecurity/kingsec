"""DI wiring for secrets infrastructure."""

from __future__ import annotations

from typing import TYPE_CHECKING, Any

from kingsec.application.ports.outbound.encryption_service import EncryptionServicePort
from kingsec.application.ports.outbound.secret_provider import SecretProviderPort

from .encrypted_file_secret_provider import EncryptedFileSecretProvider
from .environment_secret_provider import EnvironmentSecretProvider
from .fernet_encryption_service import FernetEncryptionService

if TYPE_CHECKING:
    from kingsec.bootstrap.container import Container


def register_secrets(container: Any, secrets_file_path: str = "secrets.json") -> None:
    encryption_service = FernetEncryptionService()
    secret_provider = EncryptedFileSecretProvider(encryption_service, secrets_file_path)

    container.register_instance(EncryptionServicePort, encryption_service)
    container.register_instance(SecretProviderPort, secret_provider)
