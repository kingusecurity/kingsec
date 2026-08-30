"""Pydantic schemas for the secrets management admin API."""

from __future__ import annotations

from pydantic import BaseModel, ConfigDict, Field


class SecretMetadataResponse(BaseModel):
    model_config = ConfigDict(extra="forbid")

    name: str
    secret_type: str
    version: int
    created_at: str
    updated_at: str
    masked_value: str


class ListSecretsResponse(BaseModel):
    model_config = ConfigDict(extra="forbid")

    items: list[SecretMetadataResponse]


class SecretStatusResponse(BaseModel):
    model_config = ConfigDict(extra="forbid")

    encryption_enabled: bool
    provider_type: str
    stored_secrets_count: int
    encryption_version: str


class StoreSecretBody(BaseModel):
    model_config = ConfigDict(extra="forbid")

    name: str = Field(..., min_length=1, max_length=256)
    # 8192: generous enough for any realistic credential this endpoint
    # stores (per SecretType: passwords, API keys, JWT/webhook secrets,
    # SSH/cloud credentials - including PEM-encoded private keys or
    # certificates, which run to a few KB) while still bounding the
    # field, since no explicit domain/database limit exists for it.
    value: str = Field(..., min_length=1, max_length=8192, description="The plaintext secret value")
    # 64: SecretType's longest defined value is 18 characters
    # ("database_password"/"scanner_credential") - generous margin for
    # future enum additions.
    secret_type: str = Field(default="database_password", max_length=64, description="Type of secret")


class StoreSecretResponse(BaseModel):
    model_config = ConfigDict(extra="forbid")

    name: str
    secret_type: str
    version: int
    created_at: str
    updated_at: str
    masked_value: str


class RotateSecretsResponse(BaseModel):
    model_config = ConfigDict(extra="forbid")

    reencrypted_count: int
    new_key_fingerprint: str
