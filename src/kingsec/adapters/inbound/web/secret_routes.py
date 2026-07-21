"""Admin-only FastAPI endpoints for enterprise secrets management."""

from __future__ import annotations

from typing import cast

from fastapi import APIRouter, Depends, Request, status

from kingsec.application.services.configuration_security_service import ConfigurationSecurityService
from kingsec.application.use_cases.delete_secret import DeleteSecret
from kingsec.application.use_cases.list_secrets import ListSecrets
from kingsec.application.use_cases.rotate_secrets import RotateSecrets
from kingsec.application.use_cases.secret_dto import (
    DeleteSecretRequest,
    ListSecretsRequest,
    RotateSecretsRequest,
    StoreSecretRequest,
)
from kingsec.application.use_cases.store_secret import StoreSecret
from kingsec.bootstrap.application import Application

from .auth import require_admin
from .secret_schemas import (
    ListSecretsResponse,
    RotateSecretsResponse,
    SecretMetadataResponse,
    SecretStatusResponse,
    StoreSecretBody,
    StoreSecretResponse,
)

router = APIRouter(prefix="/api/v1/admin", dependencies=[Depends(require_admin)])


def _get_store_secret_uc(request: Request) -> StoreSecret:
    app: Application = request.app.state.kingsec_app
    return cast(StoreSecret, app.resolve(StoreSecret))


def _get_list_secrets_uc(request: Request) -> ListSecrets:
    app: Application = request.app.state.kingsec_app
    return cast(ListSecrets, app.resolve(ListSecrets))


def _get_delete_secret_uc(request: Request) -> DeleteSecret:
    app: Application = request.app.state.kingsec_app
    return cast(DeleteSecret, app.resolve(DeleteSecret))


def _get_rotate_secrets_uc(request: Request) -> RotateSecrets:
    app: Application = request.app.state.kingsec_app
    return cast(RotateSecrets, app.resolve(RotateSecrets))


def _get_config_security_service(request: Request) -> ConfigurationSecurityService:
    app: Application = request.app.state.kingsec_app
    return cast(ConfigurationSecurityService, app.resolve(ConfigurationSecurityService))


@router.get(
    "/secrets",
    response_model=ListSecretsResponse,
    tags=["secrets"],
    summary="List secret metadata",
    description="List all stored secrets — returns metadata only, never plaintext.",
    responses={
        200: {"description": "List of secret metadata"},
        401: {"description": "Missing or invalid token"},
        403: {"description": "Insufficient permissions (ADMIN required)"},
    },
)
async def list_secrets(
    list_uc: ListSecrets = Depends(_get_list_secrets_uc),
) -> ListSecretsResponse:
    result = list_uc.execute(ListSecretsRequest())
    return ListSecretsResponse(
        items=[
            SecretMetadataResponse(
                name=s.name,
                secret_type=s.secret_type.value,
                version=s.version,
                created_at=s.created_at,
                updated_at=s.updated_at,
                masked_value=s.masked_value,
            )
            for s in result.secrets
        ],
    )


@router.get(
    "/secrets/status",
    response_model=SecretStatusResponse,
    tags=["secrets"],
    summary="Encryption status",
    description="Returns encryption enabled status, provider type, count, and version.",
    responses={
        200: {"description": "Encryption status"},
        401: {"description": "Missing or invalid token"},
        403: {"description": "Insufficient permissions (ADMIN required)"},
    },
)
async def get_secrets_status(
    config_svc: ConfigurationSecurityService = Depends(_get_config_security_service),
) -> SecretStatusResponse:
    status_data = config_svc.get_encryption_status()
    return SecretStatusResponse(
        encryption_enabled=status_data["encryption_enabled"],
        provider_type=status_data["provider_type"],
        stored_secrets_count=status_data["stored_secrets_count"],
        encryption_version=status_data["encryption_version"],
    )


@router.post(
    "/secrets",
    response_model=StoreSecretResponse,
    status_code=status.HTTP_201_CREATED,
    tags=["secrets"],
    summary="Store a secret",
    description="Encrypt and store a new secret. Returns metadata only.",
    responses={
        201: {"description": "Secret stored"},
        400: {"description": "Validation error"},
        401: {"description": "Missing or invalid token"},
        403: {"description": "Insufficient permissions (ADMIN required)"},
    },
)
async def store_secret(
    body: StoreSecretBody,
    store_uc: StoreSecret = Depends(_get_store_secret_uc),
) -> StoreSecretResponse:
    result = store_uc.execute(
        StoreSecretRequest(
            name=body.name,
            plaintext=body.value,
            secret_type=body.secret_type,
        )
    )
    return StoreSecretResponse(
        name=result.metadata.name,
        secret_type=result.metadata.secret_type.value,
        version=result.metadata.version,
        created_at=result.metadata.created_at,
        updated_at=result.metadata.updated_at,
        masked_value=result.metadata.masked_value,
    )


@router.delete(
    "/secrets/{name}",
    status_code=status.HTTP_204_NO_CONTENT,
    tags=["secrets"],
    summary="Delete a secret",
    description="Permanently delete a stored secret by name.",
    responses={
        204: {"description": "Secret deleted"},
        401: {"description": "Missing or invalid token"},
        403: {"description": "Insufficient permissions (ADMIN required)"},
        404: {"description": "Secret not found"},
    },
)
async def delete_secret(
    name: str,
    delete_uc: DeleteSecret = Depends(_get_delete_secret_uc),
) -> None:
    delete_uc.execute(DeleteSecretRequest(name=name))


@router.post(
    "/secrets/rotate",
    response_model=RotateSecretsResponse,
    tags=["secrets"],
    summary="Rotate encryption key",
    description="Rotate the encryption key and re-encrypt all stored secrets.",
    responses={
        200: {"description": "Key rotated"},
        401: {"description": "Missing or invalid token"},
        403: {"description": "Insufficient permissions (ADMIN required)"},
    },
)
async def rotate_secrets(
    rotate_uc: RotateSecrets = Depends(_get_rotate_secrets_uc),
) -> RotateSecretsResponse:
    result = rotate_uc.execute(RotateSecretsRequest())
    return RotateSecretsResponse(
        reencrypted_count=result.reencrypted_count,
        new_key_fingerprint=result.new_key_fingerprint,
    )
