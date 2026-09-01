"""Regression tests for identity-provider (SSO) route authorization.

Phase 65 remediation of KSEC-64-01: identity_routes.py's mutating routes
(create/update/delete/activate/deactivate a provider) previously depended
only on get_current_user() - any authenticated user of any role, including
a freshly self-registered Viewer, could create and activate an Identity
Provider whose role_mappings resolve to Role.ADMIN (see
RoleMappingService.resolve_role() / JITProvisioningService.provision()),
making IdP configuration a de-facto privileged security control. The fix
adds require_admin to every mutating route.

Same real-boundary pattern as test_rbac.py / test_worker_routes_authorization.py:
a real FastAPI app is built with the actual identity_routes.py router
included, backed by real Login/RegisterUser/TokenService wiring so a
genuine JWT is minted and verified through the real auth dependency
chain - not a dependency_overrides shortcut that would bypass the check
under test. The IdentityProviderService itself is also real, backed by a
minimal in-memory repository, so the "intended role passes" assertions
prove full end-to-end success (200/201), not merely "didn't 403".
"""

from __future__ import annotations

import uuid

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient

from kingsec.application import Login, RefreshToken, RegisterUser, ValidateApiKey
from kingsec.application.auth import AuthorizationService
from kingsec.application.idp.ports import IdentityProviderRepositoryPort
from kingsec.application.idp.provider_service import IdentityProviderService
from kingsec.application.ports import ApiKeyHasher, ApiKeyRepository, TokenService
from kingsec.application.use_cases.check_rate_limit import CheckRateLimit
from kingsec.domain.api_key import ApiKey, ApiKeyScope
from kingsec.domain.identity import IdentityProvider
from kingsec.domain.rate_limit import LockoutPolicy
from kingsec.infrastructure.config import Settings

from .test_rbac import (
    StubClock,
    StubHasher,
    StubLockoutRepo,
    StubMfaSecretRepo,
    StubRateLimiter,
    StubTokenService,
    StubUserRepo,
    _login,
    _promote_user_in_repo,
    _register_user,
    _register_viewer,
)


class StubApiKeyHasher(ApiKeyHasher):
    """Same shape as test_api_key_integration.py's - kept local rather
    than imported to avoid coupling this authorization test file to
    that one's unrelated CRUD wiring."""

    def hash(self, plaintext_key: str) -> str:
        return f"hashed:{plaintext_key}"

    def verify(self, plaintext_key: str, key_hash: str) -> bool:
        return key_hash == f"hashed:{plaintext_key}"


class StubApiKeyRepository(ApiKeyRepository):
    def __init__(self) -> None:
        self._keys: dict[str, ApiKey] = {}

    def find_by_id(self, api_key_id: str) -> ApiKey | None:
        return self._keys.get(api_key_id)

    def find_by_user_id(self, user_id: str, limit: int = 50, offset: int = 0) -> list[ApiKey]:
        return [k for k in self._keys.values() if k.user_id == user_id][offset : offset + limit]

    def save(self, key: ApiKey) -> None:
        self._keys[key.id] = key

    def delete(self, api_key_id: str) -> None:
        self._keys.pop(api_key_id, None)

    def count_by_user(self, user_id: str) -> int:
        return sum(1 for k in self._keys.values() if k.user_id == user_id)

    def count_all(self) -> int:
        return len(self._keys)

# ── Minimal in-memory identity-provider repository (auth is what's under
#    test, not IdP business logic) ──────────────────────────────────────


class InMemoryIdpRepo(IdentityProviderRepositoryPort):
    def __init__(self) -> None:
        self._providers: dict[str, IdentityProvider] = {}

    def save(self, provider: IdentityProvider) -> IdentityProvider:
        self._providers[provider.id] = provider
        return provider

    def get(self, provider_id: str) -> IdentityProvider | None:
        return self._providers.get(provider_id)

    def find_all(self) -> list[IdentityProvider]:
        return list(self._providers.values())

    def find_by_protocol(self, protocol: str) -> list[IdentityProvider]:
        return [p for p in self._providers.values() if p.protocol.value == protocol]

    def find_by_domain(self, domain: str) -> list[IdentityProvider]:
        return [p for p in self._providers.values() if p.domain_hint == domain]

    def find_active(self) -> list[IdentityProvider]:
        return [p for p in self._providers.values() if p.status.value == "active"]

    def delete(self, provider_id: str) -> None:
        self._providers.pop(provider_id, None)


# ── App builder (mirrors test_worker_routes_authorization.py's
#    _build_app, plus the identity router and a real IdentityProviderService) ──


def _build_app() -> tuple[FastAPI, StubUserRepo, InMemoryIdpRepo, StubApiKeyRepository, StubApiKeyHasher]:
    token_service = StubTokenService()
    user_repo = StubUserRepo()
    hasher = StubHasher()
    idp_repo = InMemoryIdpRepo()
    idp_service = IdentityProviderService(idp_repo)
    api_key_repo = StubApiKeyRepository()
    api_key_hasher = StubApiKeyHasher()

    app = FastAPI()

    class _StubApp:
        settings = Settings()

        def resolve(self, service_type: type):
            from kingsec.application.ports import PasswordHasher, ServiceAPI, UserRepository

            if service_type == TokenService:
                return token_service
            if service_type == UserRepository:
                return user_repo
            if service_type == PasswordHasher:
                return hasher
            if service_type == RegisterUser:
                return RegisterUser(user_repo, hasher)
            if service_type == Login:
                return Login(
                    user_repo,
                    hasher,
                    token_service,
                    StubLockoutRepo(),
                    StubClock(),
                    LockoutPolicy(max_attempts=5, lockout_duration_seconds=900),
                    StubMfaSecretRepo(),
                )
            if service_type == RefreshToken:
                return RefreshToken(user_repo, token_service)
            if service_type == AuthorizationService:
                return AuthorizationService()
            if service_type == CheckRateLimit:
                return CheckRateLimit(StubRateLimiter())
            if service_type == IdentityProviderService:
                return idp_service
            if service_type == ValidateApiKey:
                return ValidateApiKey(api_key_repo, api_key_hasher)
            if service_type == ServiceAPI:
                raise ValueError("ServiceAPI not needed by these tests")
            from kingsec.application.services.licensing import LicenseGate

            if service_type == LicenseGate:
                return None
            raise ValueError(f"Unknown service: {service_type}")

    app.state.kingsec_app = _StubApp()  # type: ignore[attr-defined]

    from kingsec.adapters.inbound.web.error_handlers import register_error_handlers
    from kingsec.adapters.inbound.web.identity_routes import router as identity_router
    from kingsec.adapters.inbound.web.routes import router as auth_router

    register_error_handlers(app)
    app.include_router(auth_router)
    app.include_router(identity_router)

    return app, user_repo, idp_repo, api_key_repo, api_key_hasher


# ── Tests ──────────────────────────────────────────────────────────────

_IDP_MUTATIONS: list[tuple[str, str, dict | None]] = [
    ("POST", "/api/v1/identity/providers", {"name": "evil-idp", "protocol": "oidc"}),
    ("PUT", "/api/v1/identity/providers/does-not-exist", {"name": "renamed"}),
    ("DELETE", "/api/v1/identity/providers/does-not-exist", None),
    ("POST", "/api/v1/identity/providers/does-not-exist/activate", None),
    ("POST", "/api/v1/identity/providers/does-not-exist/deactivate", None),
]


class TestIdentityAuthorizationUnauthenticated:
    """No credential at all -> 401, for every identity-provider mutation."""

    def setup_method(self) -> None:
        self.app, self._ur, self._idp, self._key_repo, self._key_hasher = _build_app()
        self.client = TestClient(self.app)

    @pytest.mark.parametrize("method,path,body", _IDP_MUTATIONS)
    def test_identity_mutation_returns_401_without_token(self, method: str, path: str, body: dict | None) -> None:
        resp = self.client.request(method, path, json=body)
        assert resp.status_code == 401, f"{method} {path} returned {resp.status_code}: {resp.text}"


class TestIdentityAuthorizationViewer:
    """Viewer (a real, self-registered default role) -> 403 on every
    identity-provider mutation - this is the exact KSEC-64-01 boundary."""

    def setup_method(self) -> None:
        self.app, self._ur, self._idp, self._key_repo, self._key_hasher = _build_app()
        self.client = TestClient(self.app)

    @pytest.mark.parametrize("method,path,body", _IDP_MUTATIONS)
    def test_viewer_cannot_mutate_identity_providers(self, method: str, path: str, body: dict | None) -> None:
        _register_viewer(self.client)
        token = _login(self.client)

        resp = self.client.request(method, path, json=body, headers={"Authorization": f"Bearer {token}"})
        assert resp.status_code == 403, f"{method} {path} returned {resp.status_code}: {resp.text}"


class TestIdentityAuthorizationAnalyst:
    """Analyst -> 403 on every identity-provider mutation (IdP config is
    admin-only, matching secret_routes.py/integration_routes.py, not an
    analyst-accessible surface)."""

    def setup_method(self) -> None:
        self.app, self._ur, self._idp, self._key_repo, self._key_hasher = _build_app()
        self.client = TestClient(self.app)

    @pytest.mark.parametrize("method,path,body", _IDP_MUTATIONS)
    def test_analyst_cannot_mutate_identity_providers(self, method: str, path: str, body: dict | None) -> None:
        _register_user(self.client, username="analyst1", email="analyst1@example.com")
        _promote_user_in_repo(self._ur, "analyst1", "analyst")
        token = _login(self.client, username="analyst1")

        resp = self.client.request(method, path, json=body, headers={"Authorization": f"Bearer {token}"})
        assert resp.status_code == 403, f"{method} {path} returned {resp.status_code}: {resp.text}"


class TestIdentityAuthorizationAdmin:
    """Admin -> the real fix doesn't break legitimate access. Exercised
    through the real create -> update -> activate -> deactivate -> delete
    lifecycle, not just a single smoke request."""

    def setup_method(self) -> None:
        self.app, self._ur, self._idp, self._key_repo, self._key_hasher = _build_app()
        self.client = TestClient(self.app)

    def _admin_token(self) -> str:
        # The very first registered user is auto-promoted to Admin.
        _register_user(self.client, username="admin1", email="admin1@example.com")
        return _login(self.client, username="admin1")

    def test_admin_can_create_update_activate_deactivate_and_delete_a_provider(self) -> None:
        token = self._admin_token()
        headers = {"Authorization": f"Bearer {token}"}

        created = self.client.post(
            "/api/v1/identity/providers",
            json={"name": "corp-okta", "protocol": "oidc"},
            headers=headers,
        )
        assert created.status_code == 200, created.text
        provider_id = created.json()["provider"]["id"]

        updated = self.client.put(
            f"/api/v1/identity/providers/{provider_id}",
            json={"name": "corp-okta-renamed"},
            headers=headers,
        )
        assert updated.status_code == 200, updated.text
        assert updated.json()["provider"]["name"] == "corp-okta-renamed"

        activated = self.client.post(f"/api/v1/identity/providers/{provider_id}/activate", headers=headers)
        assert activated.status_code == 200, activated.text
        assert activated.json()["provider"]["status"] == "active"

        deactivated = self.client.post(f"/api/v1/identity/providers/{provider_id}/deactivate", headers=headers)
        assert deactivated.status_code == 200, deactivated.text
        assert deactivated.json()["provider"]["status"] == "inactive"

        deleted = self.client.delete(f"/api/v1/identity/providers/{provider_id}", headers=headers)
        assert deleted.status_code == 200, deleted.text

        gone = self.client.get("/api/v1/identity/providers", headers=headers)
        assert gone.status_code == 200
        assert gone.json()["total"] == 0


class TestIdentityAuthorizationReadRoutesRemainViewerAccessible:
    """POST /test (connection-test) was never part of KSEC-64-01/
    KSEC-75-06 and must stay reachable by any authenticated user - it
    only validates the shape of a caller-supplied config body and never
    touches persisted provider data."""

    def setup_method(self) -> None:
        self.app, self._ur, self._idp, self._key_repo, self._key_hasher = _build_app()
        self.client = TestClient(self.app)

    def test_viewer_can_test_a_connection(self) -> None:
        _register_viewer(self.client)
        token = _login(self.client)
        resp = self.client.post(
            "/api/v1/identity/test",
            json={"name": "corp-okta", "protocol": "oidc"},
            headers={"Authorization": f"Bearer {token}"},
        )
        assert resp.status_code == 200, resp.text


class TestIdentityAuthorizationReadRoutesAreAdminOnly:
    """KSEC-75-06: GET /api/v1/identity/providers and GET
    /api/v1/identity/providers/{id} previously depended only on
    get_current_user() - any authenticated role (or a non-admin API
    key) could enumerate SSO/LDAP integration metadata (entity IDs,
    SSO/authorization URLs, LDAP bind_dn/base_dn, domain hints). The fix
    adds require_admin, matching the mutating routes on this same
    router."""

    def setup_method(self) -> None:
        self.app, self._ur, self._idp, self._key_repo, self._key_hasher = _build_app()
        self.client = TestClient(self.app)

    def _admin_headers(self) -> dict[str, str]:
        _register_user(self.client, username="admin1", email="admin1@example.com")
        token = _login(self.client, username="admin1")
        return {"Authorization": f"Bearer {token}"}

    def test_admin_can_list_and_get_providers(self) -> None:
        headers = self._admin_headers()
        created = self.client.post(
            "/api/v1/identity/providers",
            json={
                "name": "corp-okta",
                "protocol": "saml2",
                "saml_config": {"certificate": "-----BEGIN CERTIFICATE-----fake-----END CERTIFICATE-----"},
            },
            headers=headers,
        )
        assert created.status_code == 200, created.text
        provider_id = created.json()["provider"]["id"]

        listed = self.client.get("/api/v1/identity/providers", headers=headers)
        assert listed.status_code == 200, listed.text
        assert listed.json()["total"] == 1

        fetched = self.client.get(f"/api/v1/identity/providers/{provider_id}", headers=headers)
        assert fetched.status_code == 200, fetched.text

    def test_viewer_cannot_list_providers(self) -> None:
        _register_viewer(self.client)
        token = _login(self.client)
        resp = self.client.get(
            "/api/v1/identity/providers",
            headers={"Authorization": f"Bearer {token}"},
        )
        assert resp.status_code == 403, resp.text

    def test_viewer_cannot_get_a_provider(self) -> None:
        _register_viewer(self.client)
        token = _login(self.client)
        resp = self.client.get(
            "/api/v1/identity/providers/does-not-exist",
            headers={"Authorization": f"Bearer {token}"},
        )
        assert resp.status_code == 403, resp.text

    def test_analyst_cannot_list_providers(self) -> None:
        _register_user(self.client, username="analyst1", email="analyst1@example.com")
        _promote_user_in_repo(self._ur, "analyst1", "analyst")
        token = _login(self.client, username="analyst1")
        resp = self.client.get(
            "/api/v1/identity/providers",
            headers={"Authorization": f"Bearer {token}"},
        )
        assert resp.status_code == 403, resp.text

    def test_non_admin_read_only_api_key_cannot_list_providers(self) -> None:
        """A non-admin, read_only-scoped API key must not gain access
        either - require_admin checks the KEY OWNER's role, not the
        key's own scope, so a Viewer-owned key is rejected regardless
        of scope."""
        _register_viewer(self.client)
        viewer = self._ur.find_by_username("testuser")
        assert viewer is not None

        key_id = str(uuid.uuid4())
        plaintext_key = f"ks_{key_id}_supersecret"
        self._key_repo.save(
            ApiKey(
                id=key_id,
                user_id=viewer.id,
                name="ci-key",
                key_hash=self._key_hasher.hash(plaintext_key),
                scope=ApiKeyScope.READ_ONLY,
            )
        )

        resp = self.client.get(
            "/api/v1/identity/providers",
            headers={"X-API-Key": plaintext_key},
        )
        assert resp.status_code == 403, resp.text

    def test_provider_secrets_are_never_exposed_to_admin_either(self) -> None:
        """Even the admin-only response must never leak
        Saml2Config.private_key / OidcConfig.client_secret /
        LdapConfig.bind_password / OAuth2Config.client_secret."""
        headers = self._admin_headers()
        created = self.client.post(
            "/api/v1/identity/providers",
            json={
                "name": "corp-okta",
                "protocol": "oidc",
                "oidc_config": {"client_id": "abc123", "client_secret": "TOP-SECRET-VALUE"},
            },
            headers=headers,
        )
        assert created.status_code == 200, created.text
        provider_id = created.json()["provider"]["id"]

        fetched = self.client.get(f"/api/v1/identity/providers/{provider_id}", headers=headers)
        assert fetched.status_code == 200, fetched.text
        body_text = fetched.text
        assert "TOP-SECRET-VALUE" not in body_text
        assert "client_secret" not in fetched.json()["provider"]["oidc_config"]
