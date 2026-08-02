"""API routes for Identity Providers (SSO) management."""

from __future__ import annotations

from typing import TYPE_CHECKING, Any, cast

from fastapi import APIRouter, Depends, HTTPException, Request, status

from kingsec.application.errors import IdentityProviderNotFoundError
from kingsec.application.idp.protocol_handlers import test_provider_connection
from kingsec.application.idp.provider_service import IdentityProviderService

from .auth import CurrentUser, get_current_user
from .dependencies import get_application

if TYPE_CHECKING:
    from kingsec.bootstrap.application import Application

router = APIRouter(prefix="/api/v1/identity", tags=["identity"])


def _get_idp_service(request: Request) -> IdentityProviderService:
    app: Application = get_application(request)
    return cast(IdentityProviderService, app.resolve(IdentityProviderService))


@router.get("/providers")
async def list_providers(
    request: Request,
    user: CurrentUser = Depends(get_current_user),
) -> dict[str, Any]:
    service = _get_idp_service(request)
    providers = service.list_all()
    return {
        "providers": [
            {
                "id": p.id,
                "name": p.name,
                "protocol": p.protocol.value,
                "status": p.status.value,
                "issuer": p.issuer,
                "domain_hint": p.domain_hint,
                "jit_provisioning": p.jit_provisioning,
                "auto_link_users": p.auto_link_users,
                "enforce_sso": p.enforce_sso,
                "organization_id": p.organization_id,
                "created_at": p.created_at,
                "updated_at": p.updated_at,
            }
            for p in providers
        ],
        "total": len(providers),
    }


@router.post("/providers")
async def create_provider(
    request: Request,
    body: dict[str, Any],
    user: CurrentUser = Depends(get_current_user),
) -> dict[str, Any]:
    if not body.get("name"):
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="name is required")
    if not body.get("protocol"):
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="protocol is required")
    service = _get_idp_service(request)
    try:
        provider = service.create(
            name=body["name"],
            protocol=body["protocol"],
            issuer=body.get("issuer", ""),
            domain_hint=body.get("domain_hint", ""),
            role_mappings=body.get("role_mappings"),
            group_mappings=body.get("group_mappings"),
            jit_provisioning=body.get("jit_provisioning", False),
            auto_link_users=body.get("auto_link_users", False),
            enforce_sso=body.get("enforce_sso", False),
            saml_config=body.get("saml_config"),
            oidc_config=body.get("oidc_config"),
            ldap_config=body.get("ldap_config"),
            oauth2_config=body.get("oauth2_config"),
            organization_id=body.get("organization_id", ""),
            created_by=user.user_id,
            metadata_xml=body.get("metadata_xml", ""),
        )
    except ValueError as exc:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(exc)) from exc
    return {
        "message": "Identity provider created",
        "provider": {
            "id": provider.id,
            "name": provider.name,
            "protocol": provider.protocol.value,
            "status": provider.status.value,
        },
    }


@router.get("/providers/{provider_id}")
async def get_provider(
    provider_id: str,
    request: Request,
    user: CurrentUser = Depends(get_current_user),
) -> dict[str, Any]:
    service = _get_idp_service(request)
    try:
        p = service.get(provider_id)
    except IdentityProviderNotFoundError as exc:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=str(exc)) from exc
    return {
        "provider": {
            "id": p.id,
            "name": p.name,
            "protocol": p.protocol.value,
            "status": p.status.value,
            "issuer": p.issuer,
            "domain_hint": p.domain_hint,
            "role_mappings": [
                {"external_group": r.external_group, "kingsec_role": r.kingsec_role, "priority": r.priority}
                for r in p.role_mappings
            ],
            "group_mappings": [
                {"external_group": g.external_group, "kingsec_role": g.kingsec_role, "organization_id": g.organization_id}
                for g in p.group_mappings
            ],
            "jit_provisioning": p.jit_provisioning,
            "auto_link_users": p.auto_link_users,
            "enforce_sso": p.enforce_sso,
            "metadata_xml": p.metadata_xml,
            "saml_config": {
                "entity_id": p.saml_config.entity_id,
                "sso_url": p.saml_config.sso_url,
                "slo_url": p.saml_config.slo_url,
                "certificate": p.saml_config.certificate,
                "name_id_format": p.saml_config.name_id_format,
                "assertion_encrypted": p.saml_config.assertion_encrypted,
                "authn_context": p.saml_config.authn_context,
                "signature_algorithm": p.saml_config.signature_algorithm,
                "metadata_url": p.saml_config.metadata_url,
                "clock_skew_seconds": p.saml_config.clock_skew_seconds,
            },
            "oidc_config": {
                "issuer_url": p.oidc_config.issuer_url,
                "client_id": p.oidc_config.client_id,
                "authorization_url": p.oidc_config.authorization_url,
                "token_url": p.oidc_config.token_url,
                "userinfo_url": p.oidc_config.userinfo_url,
                "jwks_url": p.oidc_config.jwks_url,
                "end_session_url": p.oidc_config.end_session_url,
                "scopes": list(p.oidc_config.scopes),
                "subject_claim": p.oidc_config.subject_claim,
                "clock_skew_seconds": p.oidc_config.clock_skew_seconds,
            },
            "ldap_config": {
                "server_url": p.ldap_config.server_url,
                "bind_dn": p.ldap_config.bind_dn,
                "base_dn": p.ldap_config.base_dn,
                "user_filter": p.ldap_config.user_filter,
                "group_filter": p.ldap_config.group_filter,
                "username_attribute": p.ldap_config.username_attribute,
                "email_attribute": p.ldap_config.email_attribute,
                "display_name_attribute": p.ldap_config.display_name_attribute,
                "group_member_attribute": p.ldap_config.group_member_attribute,
                "use_tls": p.ldap_config.use_tls,
                "timeout_seconds": p.ldap_config.timeout_seconds,
            },
            "oauth2_config": {
                "authorize_url": p.oauth2_config.authorize_url,
                "token_url": p.oauth2_config.token_url,
                "client_id": p.oauth2_config.client_id,
                "scopes": list(p.oauth2_config.scopes),
                "userinfo_endpoint": p.oauth2_config.userinfo_endpoint,
                "subject_claim": p.oauth2_config.subject_claim,
            },
            "organization_id": p.organization_id,
            "created_by": p.created_by,
            "created_at": p.created_at,
            "updated_at": p.updated_at,
        }
    }


@router.put("/providers/{provider_id}")
async def update_provider(
    provider_id: str,
    request: Request,
    body: dict[str, Any],
    user: CurrentUser = Depends(get_current_user),
) -> dict[str, Any]:
    service = _get_idp_service(request)
    try:
        provider = service.update(provider_id, **body)
    except IdentityProviderNotFoundError as exc:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=str(exc)) from exc
    except ValueError as exc:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(exc)) from exc
    return {
        "message": "Identity provider updated",
        "provider": {
            "id": provider.id,
            "name": provider.name,
            "protocol": provider.protocol.value,
            "status": provider.status.value,
        },
    }


@router.delete("/providers/{provider_id}")
async def delete_provider(
    provider_id: str,
    request: Request,
    user: CurrentUser = Depends(get_current_user),
) -> dict[str, Any]:
    service = _get_idp_service(request)
    try:
        service.delete(provider_id)
    except IdentityProviderNotFoundError as exc:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=str(exc)) from exc
    return {"message": f"Identity provider '{provider_id}' deleted"}


@router.post("/providers/{provider_id}/activate")
async def activate_provider(
    provider_id: str,
    request: Request,
    user: CurrentUser = Depends(get_current_user),
) -> dict[str, Any]:
    service = _get_idp_service(request)
    try:
        provider = service.activate(provider_id)
    except IdentityProviderNotFoundError as exc:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=str(exc)) from exc
    return {
        "message": "Identity provider activated",
        "provider": {"id": provider.id, "status": provider.status.value},
    }


@router.post("/providers/{provider_id}/deactivate")
async def deactivate_provider(
    provider_id: str,
    request: Request,
    user: CurrentUser = Depends(get_current_user),
) -> dict[str, Any]:
    service = _get_idp_service(request)
    try:
        provider = service.deactivate(provider_id)
    except IdentityProviderNotFoundError as exc:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=str(exc)) from exc
    return {
        "message": "Identity provider deactivated",
        "provider": {"id": provider.id, "status": provider.status.value},
    }


@router.post("/test")
async def test_connection(
    request: Request,
    body: dict[str, Any],
    user: CurrentUser = Depends(get_current_user),
) -> dict[str, Any]:
    """Test connection to an identity provider."""
    # Create a temporary provider object from the request body
    from datetime import UTC, datetime
    from uuid import uuid4

    from kingsec.domain.identity import (
        GroupMapping,
        IdentityProvider,
        IdentityProviderStatus,
        LdapConfig,
        OAuth2Config,
        OidcConfig,
        ProtocolType,
        RoleMappingRule,
        Saml2Config,
    )

    provider = IdentityProvider(
        id=str(uuid4()),
        name=body["name"],
        protocol=ProtocolType(body["protocol"]),
        status=IdentityProviderStatus.ACTIVE,
        issuer=body.get("issuer", ""),
        domain_hint=body.get("domain_hint", ""),
        role_mappings=tuple(RoleMappingRule(**m) for m in (body.get("role_mappings") or [])),
        group_mappings=tuple(GroupMapping(**m) for m in (body.get("group_mappings") or [])),
        jit_provisioning=body.get("jit_provisioning", False),
        auto_link_users=body.get("auto_link_users", False),
        enforce_sso=body.get("enforce_sso", False),
        metadata_xml=body.get("metadata_xml", ""),
        saml_config=Saml2Config(**(body.get("saml_config") or {})),
        oidc_config=OidcConfig(**(body.get("oidc_config") or {})),
        ldap_config=LdapConfig(**(body.get("ldap_config") or {})),
        oauth2_config=OAuth2Config(**(body.get("oauth2_config") or {})),
        organization_id=body.get("organization_id", ""),
        created_by=user.user_id,
        created_at=datetime.now(UTC).isoformat(),
        updated_at=datetime.now(UTC).isoformat(),
    )

    result = test_provider_connection(provider)
    return {
        "success": result.success,
        "message": result.message,
        "provider_name": result.provider_name,
        "protocol": result.protocol,
        "duration_ms": result.duration_ms,
        "attributes": result.attributes,
        "error": result.error,
    }
