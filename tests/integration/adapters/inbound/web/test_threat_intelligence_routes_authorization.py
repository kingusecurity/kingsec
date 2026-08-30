"""Regression tests for threat-intelligence route authorization.

Phase 65 remediation of KSEC-64-01: threat_intelligence_routes.py's
mutating operations (force-sync a CVE record, delete a CVE record, and
register a new threat feed) previously depended only on
get_current_user() - any authenticated user of any role, including a
freshly self-registered Viewer, could manipulate the threat-intelligence
data set. The fix adds require_analyst to those three routes only,
leaving the read-only summary/list/kev/epss/trend/report routes
untouched (they were never part of KSEC-64-01 and remain intentionally
available to any authenticated role).

Same real-boundary pattern as test_rbac.py / test_worker_routes_authorization.py
for the auth layer: a real FastAPI app is built with the actual
threat_intelligence_routes.py router included, backed by real
Login/RegisterUser/TokenService wiring so a genuine JWT is minted and
verified through the real auth dependency chain - the newly added
require_analyst dependency is never mocked or overridden.

ThreatIntelligenceService itself has a comparatively expensive real
dependency graph (CveEnrichmentService/EpssService/KevService/repository
ports) unrelated to the authorization question under test, so - per the
project's explicit allowance to test "the authorization dependency
boundary" when full business-operation testing is expensive - this file
overrides only the router's own _get_ti_service FastAPI dependency (via
app.dependency_overrides) with a minimal fake service, while the
independent, never-overridden require_analyst dependency runs for real
on every request.
"""

from __future__ import annotations

from datetime import UTC, datetime

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient

from kingsec.application import Login, RefreshToken, RegisterUser
from kingsec.application.auth import AuthorizationService
from kingsec.application.errors import CveNotFoundError
from kingsec.application.ports import TokenService
from kingsec.application.use_cases.check_rate_limit import CheckRateLimit
from kingsec.domain.rate_limit import LockoutPolicy
from kingsec.domain.threat_intelligence import ThreatFeedEntry, ThreatFeedType, ThreatIntelligenceSummary
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


class _FakeThreatIntelligenceService:
    """Duck-typed double covering only the three privileged methods
    under test - deliberately not a real ThreatIntelligenceService, since
    the authorization boundary (not CVE/feed business logic) is what
    this file proves."""

    async def get_summary(self) -> ThreatIntelligenceSummary:
        return ThreatIntelligenceSummary()

    async def sync_cve(self, cve_code: str):
        raise CveNotFoundError(f"{cve_code} not found (test double)")

    async def delete_cve(self, cve_id) -> None:
        return None

    async def register_feed(self, feed_type: str, title: str, source_url: str = "") -> ThreatFeedEntry:
        return ThreatFeedEntry(
            feed_id="test-feed-1",
            feed_type=ThreatFeedType.CUSTOM,
            title=title,
            source_url=source_url,
            last_synced=datetime.now(UTC).isoformat(),
        )


def _build_app() -> tuple[FastAPI, StubUserRepo]:
    token_service = StubTokenService()
    user_repo = StubUserRepo()
    hasher = StubHasher()

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
            if service_type == ServiceAPI:
                raise ValueError("ServiceAPI not needed by these tests")
            raise ValueError(f"Unknown service: {service_type}")

    app.state.kingsec_app = _StubApp()  # type: ignore[attr-defined]

    from kingsec.adapters.inbound.web.error_handlers import register_error_handlers
    from kingsec.adapters.inbound.web.routes import router as auth_router
    from kingsec.adapters.inbound.web.threat_intelligence_routes import _get_ti_service
    from kingsec.adapters.inbound.web.threat_intelligence_routes import router as ti_router

    register_error_handlers(app)
    app.include_router(auth_router)
    app.include_router(ti_router)

    # Only the service-fetching dependency is overridden - the newly
    # added require_analyst dependency on the three privileged routes is
    # NOT part of this override and runs for real on every request.
    app.dependency_overrides[_get_ti_service] = lambda: _FakeThreatIntelligenceService()

    return app, user_repo


# ── Tests ──────────────────────────────────────────────────────────────

_TI_MUTATIONS: list[tuple[str, str]] = [
    ("POST", "/api/v1/cves/CVE-2024-0001/sync"),
    ("DELETE", "/api/v1/cves/CVE-2024-0001"),
    ("POST", "/api/v1/threat-intelligence/feeds?feed_type=custom&title=test"),
]


class TestThreatIntelligenceAuthorizationUnauthenticated:
    """No credential at all -> 401, for every privileged threat-intel route."""

    def setup_method(self) -> None:
        self.app, self._ur = _build_app()
        self.client = TestClient(self.app)

    @pytest.mark.parametrize("method,path", _TI_MUTATIONS)
    def test_ti_endpoint_returns_401_without_token(self, method: str, path: str) -> None:
        resp = self.client.request(method, path)
        assert resp.status_code == 401, f"{method} {path} returned {resp.status_code}: {resp.text}"


class TestThreatIntelligenceAuthorizationViewer:
    """Viewer (a real, self-registered default role) -> 403 on every
    privileged threat-intel route - this is the exact KSEC-64-01 boundary."""

    def setup_method(self) -> None:
        self.app, self._ur = _build_app()
        self.client = TestClient(self.app)

    @pytest.mark.parametrize("method,path", _TI_MUTATIONS)
    def test_viewer_cannot_access_privileged_ti_route(self, method: str, path: str) -> None:
        _register_viewer(self.client)
        token = _login(self.client)

        resp = self.client.request(method, path, headers={"Authorization": f"Bearer {token}"})
        assert resp.status_code == 403, f"{method} {path} returned {resp.status_code}: {resp.text}"


class TestThreatIntelligenceAuthorizationAnalyst:
    """Analyst -> the required minimum role, so every privileged route
    must pass the authorization layer and reach the (fake) service."""

    def setup_method(self) -> None:
        self.app, self._ur = _build_app()
        self.client = TestClient(self.app)

    def _analyst_token(self) -> str:
        _register_user(self.client, username="admin1", email="admin1@example.com")  # first user -> Admin
        _register_user(self.client, username="analyst1", email="analyst1@example.com")
        _promote_user_in_repo(self._ur, "analyst1", "analyst")
        return _login(self.client, username="analyst1")

    def test_analyst_can_delete_and_register_feed(self) -> None:
        token = self._analyst_token()
        headers = {"Authorization": f"Bearer {token}"}

        deleted = self.client.delete("/api/v1/cves/CVE-2024-0001", headers=headers)
        assert deleted.status_code == 200, deleted.text
        assert deleted.json()["status"] == "deleted"

        registered = self.client.post(
            "/api/v1/threat-intelligence/feeds?feed_type=custom&title=test-feed",
            headers=headers,
        )
        assert registered.status_code == 200, registered.text
        assert registered.json()["title"] == "test-feed"

    def test_analyst_reaches_business_logic_on_sync(self) -> None:
        """The fake double raises CveNotFoundError for any code -> 404,
        not 401/403, proving the request passed the analyst gate."""
        token = self._analyst_token()
        headers = {"Authorization": f"Bearer {token}"}

        resp = self.client.post("/api/v1/cves/CVE-2024-0001/sync", headers=headers)
        assert resp.status_code == 404, resp.text


class TestThreatIntelligenceAuthorizationReadRoutesRemainViewerAccessible:
    """The fix must not accidentally over-restrict the read-only routes -
    summary/cves-list were never part of KSEC-64-01 and must stay
    reachable by any authenticated role."""

    def setup_method(self) -> None:
        self.app, self._ur = _build_app()
        self.client = TestClient(self.app)

    def test_viewer_can_reach_summary_route(self) -> None:
        _register_viewer(self.client)
        token = _login(self.client)
        resp = self.client.get(
            "/api/v1/threat-intelligence/summary",
            headers={"Authorization": f"Bearer {token}"},
        )
        assert resp.status_code == 200, resp.text
