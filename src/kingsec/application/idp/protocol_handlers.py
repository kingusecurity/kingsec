"""Abstract protocol handlers and test connection logic for SSO providers."""

from __future__ import annotations

from abc import ABC, abstractmethod
from datetime import UTC, datetime

from kingsec.domain.identity import IdentityProvider, SSOTestResult


class ProtocolHandler(ABC):
    @abstractmethod
    def test_connection(self, provider: IdentityProvider) -> SSOTestResult: ...


class Saml2Handler(ProtocolHandler):
    def test_connection(self, provider: IdentityProvider) -> SSOTestResult:
        start = datetime.now(UTC)
        cfg = provider.saml_config
        errors: list[str] = []
        if not cfg.entity_id:
            errors.append("Missing entity ID")
        if not cfg.sso_url:
            errors.append("Missing SSO URL")
        if not cfg.certificate:
            errors.append("Missing certificate")
        if errors:
            duration = int((datetime.now(UTC) - start).total_seconds() * 1000)
            return SSOTestResult(
                success=False,
                provider_name=provider.name,
                protocol="saml2",
                duration_ms=duration,
                error="; ".join(errors),
            )
        duration = int((datetime.now(UTC) - start).total_seconds() * 1000)
        return SSOTestResult(
            success=True,
            provider_name=provider.name,
            protocol="saml2",
            duration_ms=duration,
            attributes={
                "entity_id": cfg.entity_id,
                "sso_url": cfg.sso_url,
                "name_id_format": cfg.name_id_format,
            },
        )


class OidcHandler(ProtocolHandler):
    def test_connection(self, provider: IdentityProvider) -> SSOTestResult:
        start = datetime.now(UTC)
        cfg = provider.oidc_config
        errors: list[str] = []
        if not cfg.issuer_url:
            errors.append("Missing issuer URL")
        if not cfg.client_id:
            errors.append("Missing client ID")
        if not cfg.authorization_url:
            errors.append("Missing authorization URL")
        if errors:
            duration = int((datetime.now(UTC) - start).total_seconds() * 1000)
            return SSOTestResult(
                success=False,
                provider_name=provider.name,
                protocol="oidc",
                duration_ms=duration,
                error="; ".join(errors),
            )
        duration = int((datetime.now(UTC) - start).total_seconds() * 1000)
        return SSOTestResult(
            success=True,
            provider_name=provider.name,
            protocol="oidc",
            duration_ms=duration,
            attributes={
                "issuer": cfg.issuer_url,
                "client_id": cfg.client_id,
                "scopes": ",".join(cfg.scopes),
            },
        )


class LdapHandler(ProtocolHandler):
    def test_connection(self, provider: IdentityProvider) -> SSOTestResult:
        start = datetime.now(UTC)
        cfg = provider.ldap_config
        errors: list[str] = []
        if not cfg.server_url:
            errors.append("Missing server URL")
        if not cfg.base_dn:
            errors.append("Missing base DN")
        if errors:
            duration = int((datetime.now(UTC) - start).total_seconds() * 1000)
            return SSOTestResult(
                success=False,
                provider_name=provider.name,
                protocol="ldap",
                duration_ms=duration,
                error="; ".join(errors),
            )
        duration = int((datetime.now(UTC) - start).total_seconds() * 1000)
        return SSOTestResult(
            success=True,
            provider_name=provider.name,
            protocol="ldap",
            duration_ms=duration,
            attributes={
                "server_url": cfg.server_url,
                "base_dn": cfg.base_dn,
            },
        )


class OAuth2Handler(ProtocolHandler):
    def test_connection(self, provider: IdentityProvider) -> SSOTestResult:
        start = datetime.now(UTC)
        cfg = provider.oauth2_config
        errors: list[str] = []
        if not cfg.client_id:
            errors.append("Missing client ID")
        if not cfg.authorize_url:
            errors.append("Missing authorize URL")
        if errors:
            duration = int((datetime.now(UTC) - start).total_seconds() * 1000)
            return SSOTestResult(
                success=False,
                provider_name=provider.name,
                protocol="oauth2",
                duration_ms=duration,
                error="; ".join(errors),
            )
        duration = int((datetime.now(UTC) - start).total_seconds() * 1000)
        return SSOTestResult(
            success=True,
            provider_name=provider.name,
            protocol="oauth2",
            duration_ms=duration,
            attributes={
                "client_id": cfg.client_id,
                "authorize_url": cfg.authorize_url,
                "scopes": ",".join(cfg.scopes),
            },
        )


def get_handler(protocol: str) -> ProtocolHandler:
    handlers: dict[str, type[ProtocolHandler]] = {
        "saml2": Saml2Handler,
        "oidc": OidcHandler,
        "ldap": LdapHandler,
        "active_directory": LdapHandler,
        "oauth2": OAuth2Handler,
    }
    cls = handlers.get(protocol)
    if not cls:
        raise ValueError(f"Unsupported protocol: {protocol}")
    return cls()


def test_provider_connection(provider: IdentityProvider) -> SSOTestResult:
    handler = get_handler(provider.protocol.value)
    return handler.test_connection(provider)