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
    value: str = Field(..., min_length=1, description="The plaintext secret value")
    secret_type: str = Field(default="database_password", description="Type of secret")


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
