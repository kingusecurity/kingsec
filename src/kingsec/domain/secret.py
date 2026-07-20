"""Enterprise secret management — immutable domain value objects."""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum


class SecretType(str, Enum):
    DATABASE_PASSWORD = "database_password"
    JWT_SIGNING_KEY = "jwt_signing_key"
    JWT_REFRESH_KEY = "jwt_refresh_key"
    API_KEY_PEPPER = "api_key_pepper"
    SMTP_PASSWORD = "smtp_password"
    WEBHOOK_SECRET = "webhook_secret"
    SCANNER_CREDENTIAL = "scanner_credential"
    SSH_CREDENTIAL = "ssh_credential"
    CLOUD_CREDENTIAL = "cloud_credential"


@dataclass(frozen=True)
class SecretId:
    value: str

    def __str__(self) -> str:
        return self.value


@dataclass(frozen=True)
class SecretMetadata:
    name: str
    secret_type: SecretType
    version: int
    created_at: str
    updated_at: str
    masked_value: str

    def to_dict(self) -> dict[str, object]:
        return {
            "name": self.name,
            "secret_type": self.secret_type.value,
            "version": self.version,
            "created_at": self.created_at,
            "updated_at": self.updated_at,
            "masked_value": self.masked_value,
        }
