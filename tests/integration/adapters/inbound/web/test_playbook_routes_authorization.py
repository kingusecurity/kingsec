"""Regression tests for playbook route authorization.

Phase 65 remediation of KSEC-64-01: playbook_routes.py's mutating/
execution routes (create/update/delete/execute/enable/disable a
playbook) previously depended only on get_current_user() - any
authenticated user of any role, including a freshly self-registered
Viewer, could create and execute security-response playbooks whose
actions send Slack/Teams notifications, create Jira/GitHub tickets,
export to SIEM, mark assets critical, or change alert status. The fix
adds require_analyst to those six routes only, leaving the read-only
list/get/stats/history routes untouched (they were never part of
KSEC-64-01 and remain intentionally available to any authenticated role).

Same real-boundary pattern as test_rbac.py / test_worker_routes_authorization.py:
a real FastAPI app is built with the actual playbook_routes.py router
included, backed by real Login/RegisterUser/TokenService wiring so a
genuine JWT is minted and verified through the real auth dependency
chain. PlaybookService/PlaybookEngine are real (not faked), backed by
minimal in-memory repositories, so the "intended role passes" assertions
prove full end-to-end success, not merely "didn't 403".
"""

from __future__ import annotations

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient

from kingsec.application import Login, RefreshToken, RegisterUser
from kingsec.application.auth import AuthorizationService
from kingsec.application.playbooks.actions import ActionExecutor
from kingsec.application.playbooks.engine import PlaybookEngine
from kingsec.application.playbooks.ports import ExecutionHistoryRepositoryPort, PlaybookRepositoryPort
from kingsec.application.playbooks.service import PlaybookService
from kingsec.application.ports import TokenService
from kingsec.application.use_cases.check_rate_limit import CheckRateLimit
from kingsec.domain.playbook import ExecutionHistory, Playbook
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

# ── Minimal in-memory playbook infrastructure (auth is what's under
#    test, not playbook business logic) ─────────────────────────────────


class InMemoryPlaybookRepo(PlaybookRepositoryPort):
    def __init__(self) -> None:
        self._playbooks: dict[str, Playbook] = {}

    def save(self, playbook: Playbook) -> None:
        self._playbooks[playbook.id] = playbook

    def find_by_id(self, playbook_id: str) -> Playbook | None:
        return self._playbooks.get(playbook_id)

    def find_all(self, enabled=None, category=None, trigger_type=None, severity=None) -> list[Playbook]:
        return list(self._playbooks.values())

    def delete(self, playbook_id: str) -> None:
        self._playbooks.pop(playbook_id, None)

    def count(self) -> int:
        return len(self._playbooks)


class InMemoryExecutionHistoryRepo(ExecutionHistoryRepositoryPort):
    def __init__(self) -> None:
        self._history: dict[str, ExecutionHistory] = {}

    def save(self, history: ExecutionHistory) -> None:
        self._history[history.id] = history

    def find_by_id(self, execution_id: str) -> ExecutionHistory | None:
        return self._history.get(execution_id)

    def find_by_playbook_id(self, playbook_id: str, limit: int = 50, offset: int = 0) -> list[ExecutionHistory]:
        return [h for h in self._history.values() if h.playbook_id == playbook_id]

    def find_all(self, status=None, trigger_type=None, limit: int = 50, offset: int = 0) -> list[ExecutionHistory]:
        return list(self._history.values())

    def count(self, status=None, trigger_type=None) -> int:
        return len(self._history)

    def count_by_status(self) -> dict[str, int]:
        return {}

    def recent(self, limit: int = 10, offset: int = 0) -> list[ExecutionHistory]:
        return list(self._history.values())[:limit]

    def average_duration_ms(self) -> float:
        return 0.0

    def success_rate(self) -> float:
        return 0.0


# ── App builder (mirrors test_worker_routes_authorization.py's
#    _build_app, plus the playbook router and a real PlaybookService) ────


def _build_app() -> tuple[FastAPI, StubUserRepo]:
    token_service = StubTokenService()
    user_repo = StubUserRepo()
    hasher = StubHasher()
    playbook_repo = InMemoryPlaybookRepo()
    history_repo = InMemoryExecutionHistoryRepo()
    engine = PlaybookEngine(history_repo, ActionExecutor())
    playbook_service = PlaybookService(playbook_repo, engine, history_repo)

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
            if service_type == PlaybookService:
                return playbook_service
            if service_type == ServiceAPI:
                raise ValueError("ServiceAPI not needed by these tests")
            raise ValueError(f"Unknown service: {service_type}")

    app.state.kingsec_app = _StubApp()  # type: ignore[attr-defined]

    from kingsec.adapters.inbound.web.error_handlers import register_error_handlers
    from kingsec.adapters.inbound.web.playbook_routes import router as playbook_router
    from kingsec.adapters.inbound.web.routes import router as auth_router

    register_error_handlers(app)
    app.include_router(auth_router)
    app.include_router(playbook_router)

    return app, user_repo


# ── Tests ──────────────────────────────────────────────────────────────

_PLAYBOOK_MUTATIONS: list[tuple[str, str, dict | None]] = [
    ("POST", "/api/v1/playbooks", {"name": "evil-playbook"}),
    ("PUT", "/api/v1/playbooks/does-not-exist", {"name": "renamed"}),
    ("DELETE", "/api/v1/playbooks/does-not-exist", None),
    ("POST", "/api/v1/playbooks/does-not-exist/execute", None),
    ("POST", "/api/v1/playbooks/does-not-exist/enable", None),
    ("POST", "/api/v1/playbooks/does-not-exist/disable", None),
]


class TestPlaybookAuthorizationUnauthenticated:
    """No credential at all -> 401, for every playbook mutation/execution route."""

    def setup_method(self) -> None:
        self.app, self._ur = _build_app()
        self.client = TestClient(self.app)

    @pytest.mark.parametrize("method,path,body", _PLAYBOOK_MUTATIONS)
    def test_playbook_endpoint_returns_401_without_token(self, method: str, path: str, body: dict | None) -> None:
        resp = self.client.request(method, path, json=body)
        assert resp.status_code == 401, f"{method} {path} returned {resp.status_code}: {resp.text}"


class TestPlaybookAuthorizationViewer:
    """Viewer (a real, self-registered default role) -> 403 on every
    playbook mutation/execution route - this is the exact KSEC-64-01
    boundary."""

    def setup_method(self) -> None:
        self.app, self._ur = _build_app()
        self.client = TestClient(self.app)

    @pytest.mark.parametrize("method,path,body", _PLAYBOOK_MUTATIONS)
    def test_viewer_cannot_mutate_or_execute_playbooks(self, method: str, path: str, body: dict | None) -> None:
        _register_viewer(self.client)
        token = _login(self.client)

        resp = self.client.request(method, path, json=body, headers={"Authorization": f"Bearer {token}"})
        assert resp.status_code == 403, f"{method} {path} returned {resp.status_code}: {resp.text}"


class TestPlaybookAuthorizationAnalyst:
    """Analyst -> the required minimum role, so a real create -> update ->
    execute -> enable -> disable -> delete lifecycle must succeed, not
    just avoid a 403."""

    def setup_method(self) -> None:
        self.app, self._ur = _build_app()
        self.client = TestClient(self.app)

    def _analyst_token(self) -> str:
        _register_user(self.client, username="admin1", email="admin1@example.com")  # first user -> Admin
        _register_user(self.client, username="analyst1", email="analyst1@example.com")
        _promote_user_in_repo(self._ur, "analyst1", "analyst")
        return _login(self.client, username="analyst1")

    def test_analyst_can_create_update_execute_enable_disable_and_delete_a_playbook(self) -> None:
        token = self._analyst_token()
        headers = {"Authorization": f"Bearer {token}"}

        created = self.client.post(
            "/api/v1/playbooks",
            json={
                "name": "isolate-and-notify",
                "actions": [{"action_type": "generate_report", "config": {}}],
            },
            headers=headers,
        )
        assert created.status_code == 201, created.text
        playbook_id = created.json()["id"]

        updated = self.client.put(
            f"/api/v1/playbooks/{playbook_id}",
            json={"severity": "high"},
            headers=headers,
        )
        assert updated.status_code == 200, updated.text
        assert updated.json()["severity"] == "high"

        executed = self.client.post(f"/api/v1/playbooks/{playbook_id}/execute", headers=headers)
        assert executed.status_code == 200, executed.text

        disabled = self.client.post(f"/api/v1/playbooks/{playbook_id}/disable", headers=headers)
        assert disabled.status_code == 200, disabled.text
        assert disabled.json()["enabled"] is False

        enabled = self.client.post(f"/api/v1/playbooks/{playbook_id}/enable", headers=headers)
        assert enabled.status_code == 200, enabled.text
        assert enabled.json()["enabled"] is True

        deleted = self.client.delete(f"/api/v1/playbooks/{playbook_id}", headers=headers)
        assert deleted.status_code == 204, deleted.text

        gone = self.client.get(f"/api/v1/playbooks/{playbook_id}", headers=headers)
        assert gone.status_code == 404


class TestPlaybookAuthorizationReadRoutesRemainViewerAccessible:
    """The fix must not accidentally over-restrict the read-only routes -
    list/get/stats/history were never part of KSEC-64-01 and must stay
    reachable by any authenticated role."""

    def setup_method(self) -> None:
        self.app, self._ur = _build_app()
        self.client = TestClient(self.app)

    def test_viewer_can_list_playbooks(self) -> None:
        _register_viewer(self.client)
        token = _login(self.client)
        resp = self.client.get(
            "/api/v1/playbooks",
            headers={"Authorization": f"Bearer {token}"},
        )
        assert resp.status_code == 200, resp.text
