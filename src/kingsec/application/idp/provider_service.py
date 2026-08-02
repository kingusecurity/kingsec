"""Identity provider CRUD and lifecycle management."""

from __future__ import annotations

from datetime import UTC, datetime
from typing import Any
from uuid import uuid4

from kingsec.application.errors import IdentityProviderNotFoundError
from kingsec.application.idp.ports import IdentityProviderRepositoryPort
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


class IdentityProviderService:
    def __init__(self, repo: IdentityProviderRepositoryPort) -> None:
        self._repo = repo

    def create(
        self,
        name: str,
        protocol: str,
        issuer: str = "",
        domain_hint: str = "",
        role_mappings: list[dict[str, Any]] | None = None,
        group_mappings: list[dict[str, Any]] | None = None,
        jit_provisioning: bool = False,
        auto_link_users: bool = False,
        enforce_sso: bool = False,
        saml_config: dict[str, Any] | None = None,
        oidc_config: dict[str, Any] | None = None,
        ldap_config: dict[str, Any] | None = None,
        oauth2_config: dict[str, Any] | None = None,
        organization_id: str = "",
        created_by: str = "",
        metadata_xml: str = "",
    ) -> IdentityProvider:
        provider = IdentityProvider(
            id=str(uuid4()),
            name=name,
            protocol=ProtocolType(protocol),
            status=IdentityProviderStatus.ACTIVE,
            issuer=issuer,
            domain_hint=domain_hint,
            role_mappings=tuple(
                RoleMappingRule(**m) for m in (role_mappings or [])
            ),
            group_mappings=tuple(
                GroupMapping(**m) for m in (group_mappings or [])
            ),
            jit_provisioning=jit_provisioning,
            auto_link_users=auto_link_users,
            enforce_sso=enforce_sso,
            metadata_xml=metadata_xml,
            saml_config=Saml2Config(**(saml_config or {})),
            oidc_config=OidcConfig(**(oidc_config or {})),
            ldap_config=LdapConfig(**(ldap_config or {})),
            oauth2_config=OAuth2Config(**(oauth2_config or {})),
            organization_id=organization_id,
            created_by=created_by,
            created_at=datetime.now(UTC).isoformat(),
            updated_at=datetime.now(UTC).isoformat(),
        )
        return self._repo.save(provider)

    def update(self, provider_id: str, **kwargs: Any) -> IdentityProvider:
        existing = self._repo.get(provider_id)
        if not existing:
            raise IdentityProviderNotFoundError(f"Identity provider '{provider_id}' not found")

        name = str(kwargs.get("name", existing.name))
        protocol = ProtocolType(str(kwargs.get("protocol", existing.protocol.value)))
        issuer = str(kwargs.get("issuer", existing.issuer))
        domain_hint = str(kwargs.get("domain_hint", existing.domain_hint))

        role_mappings = existing.role_mappings
        if "role_mappings" in kwargs:
            role_mappings = tuple(
                RoleMappingRule(**m) for m in (kwargs.get("role_mappings") or [])
            )

        group_mappings = existing.group_mappings
        if "group_mappings" in kwargs:
            group_mappings = tuple(
                GroupMapping(**m) for m in (kwargs.get("group_mappings") or [])
            )

        jit_provisioning = bool(kwargs.get("jit_provisioning", existing.jit_provisioning))
        auto_link_users = bool(kwargs.get("auto_link_users", existing.auto_link_users))
        enforce_sso = bool(kwargs.get("enforce_sso", existing.enforce_sso))
        metadata_xml = str(kwargs.get("metadata_xml", existing.metadata_xml))
        organization_id = str(kwargs.get("organization_id", existing.organization_id))

        saml_config = existing.saml_config
        if "saml_config" in kwargs:
            saml_config = Saml2Config(**(kwargs.get("saml_config") or {}))

        oidc_config = existing.oidc_config
        if "oidc_config" in kwargs:
            oidc_config = OidcConfig(**(kwargs.get("oidc_config") or {}))

        ldap_config = existing.ldap_config
        if "ldap_config" in kwargs:
            ldap_config = LdapConfig(**(kwargs.get("ldap_config") or {}))

        oauth2_config = existing.oauth2_config
        if "oauth2_config" in kwargs:
            oauth2_config = OAuth2Config(**(kwargs.get("oauth2_config") or {}))

        updated = IdentityProvider(
            id=existing.id,
            name=name,
            protocol=protocol,
            status=IdentityProviderStatus(str(kwargs.get("status", existing.status.value))),
            issuer=issuer,
            domain_hint=domain_hint,
            role_mappings=role_mappings,
            group_mappings=group_mappings,
            jit_provisioning=jit_provisioning,
            auto_link_users=auto_link_users,
            enforce_sso=enforce_sso,
            metadata_xml=metadata_xml,
            saml_config=saml_config,
            oidc_config=oidc_config,
            ldap_config=ldap_config,
            oauth2_config=oauth2_config,
            organization_id=organization_id,
            created_by=existing.created_by,
            created_at=existing.created_at,
            updated_at=datetime.now(UTC).isoformat(),
        )
        return self._repo.save(updated)

    def get(self, provider_id: str) -> IdentityProvider:
        provider = self._repo.get(provider_id)
        if not provider:
            raise IdentityProviderNotFoundError(f"Identity provider '{provider_id}' not found")
        return provider

    def list_all(self) -> list[IdentityProvider]:
        return self._repo.find_all()

    def delete(self, provider_id: str) -> None:
        existing = self._repo.get(provider_id)
        if not existing:
            raise IdentityProviderNotFoundError(f"Identity provider '{provider_id}' not found")
        self._repo.delete(provider_id)

    def activate(self, provider_id: str) -> IdentityProvider:
        provider = self.get(provider_id)
        return self._repo.save(provider.activate())

    def deactivate(self, provider_id: str) -> IdentityProvider:
        provider = self.get(provider_id)
        return self._repo.save(provider.deactivate())
