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

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient

from kingsec.application import Login, RefreshToken, RegisterUser
from kingsec.application.auth import AuthorizationService
from kingsec.application.idp.ports import IdentityProviderRepositoryPort
from kingsec.application.idp.provider_service import IdentityProviderService
from kingsec.application.ports import TokenService
from kingsec.application.use_cases.check_rate_limit import CheckRateLimit
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


def _build_app() -> tuple[FastAPI, StubUserRepo, InMemoryIdpRepo]:
    token_service = StubTokenService()
    user_repo = StubUserRepo()
    hasher = StubHasher()
    idp_repo = InMemoryIdpRepo()
    idp_service = IdentityProviderService(idp_repo)

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
            if service_type == ServiceAPI:
                raise ValueError("ServiceAPI not needed by these tests")
            raise ValueError(f"Unknown service: {service_type}")

    app.state.kingsec_app = _StubApp()  # type: ignore[attr-defined]

    from kingsec.adapters.inbound.web.error_handlers import register_error_handlers
    from kingsec.adapters.inbound.web.identity_routes import router as identity_router
    from kingsec.adapters.inbound.web.routes import router as auth_router

    register_error_handlers(app)
    app.include_router(auth_router)
    app.include_router(identity_router)

    return app, user_repo, idp_repo


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
        self.app, self._ur, self._idp = _build_app()
        self.client = TestClient(self.app)

    @pytest.mark.parametrize("method,path,body", _IDP_MUTATIONS)
    def test_identity_mutation_returns_401_without_token(self, method: str, path: str, body: dict | None) -> None:
        resp = self.client.request(method, path, json=body)
        assert resp.status_code == 401, f"{method} {path} returned {resp.status_code}: {resp.text}"


class TestIdentityAuthorizationViewer:
    """Viewer (a real, self-registered default role) -> 403 on every
    identity-provider mutation - this is the exact KSEC-64-01 boundary."""

    def setup_method(self) -> None:
        self.app, self._ur, self._idp = _build_app()
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
        self.app, self._ur, self._idp = _build_app()
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
        self.app, self._ur, self._idp = _build_app()
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
    """The fix must not accidentally over-restrict the read-only routes -
    list/get/test-connection were never part of KSEC-64-01 and must stay
    reachable by any authenticated user, matching the prompt's explicit
    "do not automatically place an ADMIN dependency on an entire router"
    instruction."""

    def setup_method(self) -> None:
        self.app, self._ur, self._idp = _build_app()
        self.client = TestClient(self.app)

    def test_viewer_can_list_providers(self) -> None:
        _register_viewer(self.client)
        token = _login(self.client)
        resp = self.client.get(
            "/api/v1/identity/providers",
            headers={"Authorization": f"Bearer {token}"},
        )
        assert resp.status_code == 200, resp.text
