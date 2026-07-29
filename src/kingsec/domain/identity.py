"""Enterprise identity & SSO domain — providers, mappings, sessions."""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import UTC, datetime
from enum import StrEnum


class ProtocolType(StrEnum):
    SAML2 = "saml2"
    OIDC = "oidc"
    LDAP = "ldap"
    ACTIVE_DIRECTORY = "active_directory"
    OAUTH2 = "oauth2"


class IdentityProviderStatus(StrEnum):
    ACTIVE = "active"
    INACTIVE = "inactive"
    ERROR = "error"
    PENDING = "pending"


@dataclass(frozen=True)
class Saml2Config:
    entity_id: str = ""
    sso_url: str = ""
    slo_url: str = ""
    certificate: str = ""
    private_key: str = ""
    name_id_format: str = "urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress"
    assertion_encrypted: bool = False
    authn_context: str = ""
    signature_algorithm: str = "http://www.w3.org/2001/04/xmldsig-more#rsa-sha256"
    metadata_url: str = ""
    clock_skew_seconds: int = 120


@dataclass(frozen=True)
class OidcConfig:
    issuer_url: str = ""
    client_id: str = ""
    client_secret: str = ""
    authorization_url: str = ""
    token_url: str = ""
    userinfo_url: str = ""
    jwks_url: str = ""
    end_session_url: str = ""
    scopes: tuple[str, ...] = ("openid", "profile", "email")
    subject_claim: str = "sub"
    clock_skew_seconds: int = 120


@dataclass(frozen=True)
class LdapConfig:
    server_url: str = ""
    bind_dn: str = ""
    bind_password: str = ""
    base_dn: str = ""
    user_filter: str = "(objectClass=person)"
    group_filter: str = "(objectClass=group)"
    username_attribute: str = "sAMAccountName"
    email_attribute: str = "mail"
    display_name_attribute: str = "displayName"
    group_member_attribute: str = "member"
    use_tls: bool = True
    timeout_seconds: int = 10


@dataclass(frozen=True)
class OAuth2Config:
    authorize_url: str = ""
    token_url: str = ""
    client_id: str = ""
    client_secret: str = ""
    scopes: tuple[str, ...] = ("openid", "profile", "email")
    userinfo_endpoint: str = ""
    subject_claim: str = "sub"
    extra_params: str = ""


@dataclass(frozen=True)
class RoleMappingRule:
    external_group: str = ""
    kingsec_role: str = "viewer"
    priority: int = 0


@dataclass(frozen=True)
class GroupMapping:
    external_group: str = ""
    kingsec_role: str = "viewer"
    organization_id: str = ""


@dataclass(frozen=True)
class IdentityProvider:
    id: str
    name: str
    protocol: ProtocolType
    status: IdentityProviderStatus = IdentityProviderStatus.PENDING
    issuer: str = ""
    domain_hint: str = ""
    role_mappings: tuple[RoleMappingRule, ...] = ()
    group_mappings: tuple[GroupMapping, ...] = ()
    jit_provisioning: bool = False
    auto_link_users: bool = False
    enforce_sso: bool = False
    metadata_xml: str = ""
    saml_config: Saml2Config = field(default_factory=Saml2Config)
    oidc_config: OidcConfig = field(default_factory=OidcConfig)
    ldap_config: LdapConfig = field(default_factory=LdapConfig)
    oauth2_config: OAuth2Config = field(default_factory=OAuth2Config)
    organization_id: str = ""
    created_by: str = ""
    created_at: str = field(default_factory=lambda: datetime.now(UTC).isoformat())
    updated_at: str = field(default_factory=lambda: datetime.now(UTC).isoformat())

    def activate(self) -> IdentityProvider:
        return IdentityProvider(
            id=self.id, name=self.name, protocol=self.protocol,
            status=IdentityProviderStatus.ACTIVE, issuer=self.issuer,
            domain_hint=self.domain_hint, role_mappings=self.role_mappings,
            group_mappings=self.group_mappings, jit_provisioning=self.jit_provisioning,
            auto_link_users=self.auto_link_users, enforce_sso=self.enforce_sso,
            metadata_xml=self.metadata_xml, saml_config=self.saml_config,
            oidc_config=self.oidc_config, ldap_config=self.ldap_config,
            oauth2_config=self.oauth2_config, organization_id=self.organization_id,
            created_by=self.created_by, created_at=self.created_at,
            updated_at=datetime.now(UTC).isoformat(),
        )

    def deactivate(self) -> IdentityProvider:
        return IdentityProvider(
            id=self.id, name=self.name, protocol=self.protocol,
            status=IdentityProviderStatus.INACTIVE, issuer=self.issuer,
            domain_hint=self.domain_hint, role_mappings=self.role_mappings,
            group_mappings=self.group_mappings, jit_provisioning=self.jit_provisioning,
            auto_link_users=self.auto_link_users, enforce_sso=self.enforce_sso,
            metadata_xml=self.metadata_xml, saml_config=self.saml_config,
            oidc_config=self.oidc_config, ldap_config=self.ldap_config,
            oauth2_config=self.oauth2_config, organization_id=self.organization_id,
            created_by=self.created_by, created_at=self.created_at,
            updated_at=datetime.now(UTC).isoformat(),
        )

    def mark_error(self) -> IdentityProvider:
        return IdentityProvider(
            id=self.id, name=self.name, protocol=self.protocol,
            status=IdentityProviderStatus.ERROR, issuer=self.issuer,
            domain_hint=self.domain_hint, role_mappings=self.role_mappings,
            group_mappings=self.group_mappings, jit_provisioning=self.jit_provisioning,
            auto_link_users=self.auto_link_users, enforce_sso=self.enforce_sso,
            metadata_xml=self.metadata_xml, saml_config=self.saml_config,
            oidc_config=self.oidc_config, ldap_config=self.ldap_config,
            oauth2_config=self.oauth2_config, organization_id=self.organization_id,
            created_by=self.created_by, created_at=self.created_at,
            updated_at=datetime.now(UTC).isoformat(),
        )


@dataclass(frozen=True)
class SSOSession:
    id: str
    provider_id: str
    user_id: str
    external_user_id: str = ""
    idp_session_id: str = ""
    idp_assertion: str = ""
    attributes_json: str = ""
    session_index: str = ""
    created_at: str = field(default_factory=lambda: datetime.now(UTC).isoformat())
    expires_at: str = ""
    last_activity: str = field(default_factory=lambda: datetime.now(UTC).isoformat())
    is_active: bool = True

    def expire(self) -> SSOSession:
        return SSOSession(
            id=self.id, provider_id=self.provider_id, user_id=self.user_id,
            external_user_id=self.external_user_id, idp_session_id=self.idp_session_id,
            idp_assertion="", attributes_json=self.attributes_json,
            session_index=self.session_index, created_at=self.created_at,
            expires_at=self.expires_at, last_activity=datetime.now(UTC).isoformat(),
            is_active=False,
        )

    def record_activity(self) -> SSOSession:
        return SSOSession(
            id=self.id, provider_id=self.provider_id, user_id=self.user_id,
            external_user_id=self.external_user_id, idp_session_id=self.idp_session_id,
            idp_assertion=self.idp_assertion, attributes_json=self.attributes_json,
            session_index=self.session_index, created_at=self.created_at,
            expires_at=self.expires_at, last_activity=datetime.now(UTC).isoformat(),
            is_active=self.is_active,
        )


@dataclass(frozen=True)
class AccountLink:
    id: str
    user_id: str
    provider_id: str
    external_user_id: str
    external_username: str = ""
    external_email: str = ""
    linked_at: str = field(default_factory=lambda: datetime.now(UTC).isoformat())


@dataclass(frozen=True)
class SSOTestResult:
    success: bool
    message: str = ""
    provider_name: str = ""
    protocol: str = ""
    duration_ms: int = 0
    attributes: dict[str, str] = field(default_factory=dict)
    error: str = ""


@dataclass(frozen=True)
class IdentityProviderSummary:
    id: str
    name: str
    protocol: str
    status: str
    domain_hint: str = ""
    user_count: int = 0
    jit_provisioning: bool = False
    enforce_sso: bool = False
    created_at: str = ""
