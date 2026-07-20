"""DTOs for secret management use cases."""

from __future__ import annotations

from dataclasses import dataclass, field

from kingsec.domain.secret import SecretMetadata


@dataclass(frozen=True)
class EncryptSecretRequest:
    plaintext: str
    name: str = ""


@dataclass(frozen=True)
class EncryptSecretResponse:
    ciphertext: bytes


@dataclass(frozen=True)
class DecryptSecretRequest:
    ciphertext: bytes


@dataclass(frozen=True)
class DecryptSecretResponse:
    plaintext: str


@dataclass(frozen=True)
class RotateSecretsRequest:
    pass


@dataclass(frozen=True)
class RotateSecretsResponse:
    reencrypted_count: int
    new_key_fingerprint: str


@dataclass(frozen=True)
class StoreSecretRequest:
    name: str
    plaintext: str
    secret_type: str = "unknown"


@dataclass(frozen=True)
class StoreSecretResponse:
    metadata: SecretMetadata


@dataclass(frozen=True)
class RetrieveSecretRequest:
    name: str


@dataclass(frozen=True)
class RetrieveSecretResponse:
    plaintext: str
    metadata: SecretMetadata


@dataclass(frozen=True)
class DeleteSecretRequest:
    name: str


@dataclass(frozen=True)
class DeleteSecretResponse:
    success: bool


@dataclass(frozen=True)
class ListSecretsRequest:
    pass


@dataclass(frozen=True)
class ListSecretsResponse:
    secrets: list[SecretMetadata] = field(default_factory=list)


@dataclass(frozen=True)
class ValidateConfigurationRequest:
    required_secrets: list[str] = field(default_factory=list)


@dataclass(frozen=True)
class ValidateConfigurationResponse:
    valid: bool
    encryption_enabled: bool
    provider_type: str
    missing_secrets: list[str] = field(default_factory=list)
