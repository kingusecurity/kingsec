"""Regression tests for plugin-SDK route authorization.

Phase 65 remediation of KSEC-64-01: plugin_sdk_routes.py's privileged
operations (scan for plugins on disk, load a discovered plugin - which
dynamically imports and executes its code via PluginLoader.load(), and
unload one) previously depended only on get_current_user() - any
authenticated user of any role, including a freshly self-registered
Viewer, could trigger dynamic plugin code execution. The fix adds
require_admin to those three routes only, leaving the read-only
list/get/marketplace/permissions routes untouched (they were never part
of KSEC-64-01 and remain intentionally available to any authenticated
role).

Same real-boundary pattern as test_rbac.py / test_worker_routes_authorization.py:
a real FastAPI app is built with the actual plugin_sdk_routes.py router
included, backed by real Login/RegisterUser/TokenService wiring so a
genuine JWT is minted and verified through the real auth dependency
chain. PluginRegistry/PluginMarketplace are real (not faked), backed by
a PluginLoader pointed at an empty temp directory, so "the intended role
passes" assertions prove the request reaches real business logic, not
merely "didn't 403".
"""

from __future__ import annotations

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient

from kingsec.application import Login, RefreshToken, RegisterUser
from kingsec.application.auth import AuthorizationService
from kingsec.application.plugin_sdk.loader import PluginLoader
from kingsec.application.plugin_sdk.registry import PluginMarketplace, PluginRegistry
from kingsec.application.ports import TokenService
from kingsec.application.use_cases.check_rate_limit import CheckRateLimit
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

# ── App builder (mirrors test_worker_routes_authorization.py's
#    _build_app, plus the plugin-SDK router and real registry/marketplace) ──


def _build_app() -> tuple[FastAPI, StubUserRepo]:
    token_service = StubTokenService()
    user_repo = StubUserRepo()
    hasher = StubHasher()
    # PluginLoader.discover() returns an empty list for a directory that
    # doesn't exist (checked via Path.exists()) - no real plugin files
    # are needed to exercise authorization, only a real PluginRegistry.
    registry = PluginRegistry(PluginLoader("kingsec-test-nonexistent-plugins-dir"))
    marketplace = PluginMarketplace()

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
            if service_type == PluginRegistry:
                return registry
            if service_type == PluginMarketplace:
                return marketplace
            if service_type == ServiceAPI:
                raise ValueError("ServiceAPI not needed by these tests")
            raise ValueError(f"Unknown service: {service_type}")

    app.state.kingsec_app = _StubApp()  # type: ignore[attr-defined]

    from kingsec.adapters.inbound.web.error_handlers import register_error_handlers
    from kingsec.adapters.inbound.web.plugin_sdk_routes import router as plugin_sdk_router
    from kingsec.adapters.inbound.web.routes import router as auth_router

    register_error_handlers(app)
    app.include_router(auth_router)
    app.include_router(plugin_sdk_router)

    return app, user_repo


# ── Tests ──────────────────────────────────────────────────────────────

_PLUGIN_SDK_PRIVILEGED: list[tuple[str, str]] = [
    ("POST", "/api/v1/plugin-sdk/plugins/scan"),
    ("POST", "/api/v1/plugin-sdk/plugins/some-plugin/load"),
    ("POST", "/api/v1/plugin-sdk/plugins/some-plugin/unload"),
]


class TestPluginSdkAuthorizationUnauthenticated:
    """No credential at all -> 401, for every privileged plugin-SDK route."""

    def setup_method(self) -> None:
        self.app, self._ur = _build_app()
        self.client = TestClient(self.app)

    @pytest.mark.parametrize("method,path", _PLUGIN_SDK_PRIVILEGED)
    def test_plugin_sdk_endpoint_returns_401_without_token(self, method: str, path: str) -> None:
        resp = self.client.request(method, path)
        assert resp.status_code == 401, f"{method} {path} returned {resp.status_code}: {resp.text}"


class TestPluginSdkAuthorizationViewer:
    """Viewer (a real, self-registered default role) -> 403 on every
    privileged plugin-SDK route - this is the exact KSEC-64-01 boundary."""

    def setup_method(self) -> None:
        self.app, self._ur = _build_app()
        self.client = TestClient(self.app)

    @pytest.mark.parametrize("method,path", _PLUGIN_SDK_PRIVILEGED)
    def test_viewer_cannot_access_privileged_plugin_sdk_route(self, method: str, path: str) -> None:
        _register_viewer(self.client)
        token = _login(self.client)

        resp = self.client.request(method, path, headers={"Authorization": f"Bearer {token}"})
        assert resp.status_code == 403, f"{method} {path} returned {resp.status_code}: {resp.text}"


class TestPluginSdkAuthorizationAnalyst:
    """Analyst -> 403 on every privileged plugin-SDK route (plugin code
    execution is admin-only, matching plugin_routes.py's existing
    _require_admin pattern for the sibling plugin-upload router)."""

    def setup_method(self) -> None:
        self.app, self._ur = _build_app()
        self.client = TestClient(self.app)

    @pytest.mark.parametrize("method,path", _PLUGIN_SDK_PRIVILEGED)
    def test_analyst_cannot_access_privileged_plugin_sdk_route(self, method: str, path: str) -> None:
        _register_user(self.client, username="analyst1", email="analyst1@example.com")
        _promote_user_in_repo(self._ur, "analyst1", "analyst")
        token = _login(self.client, username="analyst1")

        resp = self.client.request(method, path, headers={"Authorization": f"Bearer {token}"})
        assert resp.status_code == 403, f"{method} {path} returned {resp.status_code}: {resp.text}"


class TestPluginSdkAuthorizationAdmin:
    """Admin -> the real fix doesn't break legitimate access. scan_plugins
    is exercised end-to-end (0 plugins in an empty directory is a
    legitimate, fully-successful result); load/unload are exercised
    against the authorization boundary (a real 404 from business logic
    for a nonexistent plugin id proves the request passed the admin gate
    and reached the registry, as distinct from being rejected at 401/403)."""

    def setup_method(self) -> None:
        self.app, self._ur = _build_app()
        self.client = TestClient(self.app)

    def _admin_token(self) -> str:
        # Phase 3: self-registration never grants Admin - promote directly
        # in the stub repo, same pattern test_rbac.py itself uses.
        _register_user(self.client, username="admin1", email="admin1@example.com")
        _promote_user_in_repo(self._ur, "admin1", "admin")
        return _login(self.client, username="admin1")

    def test_admin_can_scan_plugins(self) -> None:
        token = self._admin_token()
        headers = {"Authorization": f"Bearer {token}"}

        resp = self.client.post("/api/v1/plugin-sdk/plugins/scan", headers=headers)
        assert resp.status_code == 200, resp.text
        assert resp.json()["count"] == 0

    def test_admin_reaches_business_logic_on_load_and_unload(self) -> None:
        token = self._admin_token()
        headers = {"Authorization": f"Bearer {token}"}

        load_resp = self.client.post("/api/v1/plugin-sdk/plugins/nonexistent/load", headers=headers)
        assert load_resp.status_code == 404, load_resp.text  # not 401/403 - passed the admin gate

        unload_resp = self.client.post("/api/v1/plugin-sdk/plugins/nonexistent/unload", headers=headers)
        assert unload_resp.status_code == 200, unload_resp.text  # unload is a no-op for unknown ids


class TestPluginSdkAuthorizationReadRoutesRemainViewerAccessible:
    """The fix must not accidentally over-restrict the read-only routes -
    list/get/marketplace/permissions were never part of KSEC-64-01 and
    must stay reachable by any authenticated role."""

    def setup_method(self) -> None:
        self.app, self._ur = _build_app()
        self.client = TestClient(self.app)

    def test_viewer_can_list_sdk_plugins(self) -> None:
        _register_viewer(self.client)
        token = _login(self.client)
        resp = self.client.get(
            "/api/v1/plugin-sdk/plugins",
            headers={"Authorization": f"Bearer {token}"},
        )
        assert resp.status_code == 200, resp.text

    def test_permissions_route_remains_public_per_existing_allowlist(self) -> None:
        """GET /api/v1/plugin-sdk/permissions is intentionally listed as
        public in test_openapi_allowlist.py - confirm the fix didn't
        accidentally add auth to it."""
        resp = self.client.get("/api/v1/plugin-sdk/permissions")
        assert resp.status_code == 200, resp.text
