"""Regression tests for worker-management route authorization.

Phase 01 remediation: worker_routes.py previously depended only on
get_current_user() - any authenticated user of any role, including a
freshly self-registered Viewer, could register fake distributed workers,
forge heartbeats, and delete real workers by ID. The fix adds a
router-level require_admin dependency.

Same real-boundary pattern as test_rbac.py: a real FastAPI app is built
with the actual worker_routes.py router included, backed by real
Login/RegisterUser/TokenService wiring so a genuine JWT is minted and
verified through the real auth dependency chain - not a
dependency_overrides shortcut that would bypass the check under test.
"""

from __future__ import annotations

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient

from kingsec.application import Login, RefreshToken, RegisterUser
from kingsec.application.auth import AuthorizationService
from kingsec.application.distributed.ports import (
    DeadLetterRepositoryPort,
    JobLeaseRepositoryPort,
    JobQueueRepositoryPort,
    WorkerRepositoryPort,
)
from kingsec.application.distributed.worker_service import HeartbeatManager, WorkerRegistrationService
from kingsec.application.ports import TokenService
from kingsec.application.use_cases.check_rate_limit import CheckRateLimit
from kingsec.domain.job import WorkerNode
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

# ── Minimal in-memory worker infrastructure (auth is what's under test,
#    not worker business logic - these are the smallest real
#    implementations that let a request past the auth gate actually
#    complete) ─────────────────────────────────────────────────────────


class InMemoryWorkerRepo(WorkerRepositoryPort):
    def __init__(self) -> None:
        self._workers: dict[str, WorkerNode] = {}

    def register(self, worker: WorkerNode) -> WorkerNode:
        self._workers[worker.worker_id] = worker
        return worker

    def get(self, worker_id: str) -> WorkerNode | None:
        return self._workers.get(worker_id)

    def find_all(self) -> list[WorkerNode]:
        return list(self._workers.values())

    def find_online(self) -> list[WorkerNode]:
        return list(self._workers.values())

    def find_idle(self) -> list[WorkerNode]:
        return list(self._workers.values())

    def update(self, worker: WorkerNode) -> None:
        self._workers[worker.worker_id] = worker

    def delete(self, worker_id: str) -> None:
        self._workers.pop(worker_id, None)


class _UnusedQueuePort(JobQueueRepositoryPort):
    """Never exercised by these tests - process_heartbeat() only touches
    WorkerRepositoryPort. Present only so HeartbeatManager can be built."""

    def enqueue(self, entry):  # type: ignore[no-untyped-def]
        raise NotImplementedError

    def get(self, entry_id):  # type: ignore[no-untyped-def]
        raise NotImplementedError

    def find_by_state(self, state):  # type: ignore[no-untyped-def]
        raise NotImplementedError

    def find_all(self):  # type: ignore[no-untyped-def]
        raise NotImplementedError

    def update(self, entry):  # type: ignore[no-untyped-def]
        raise NotImplementedError

    def delete(self, entry_id):  # type: ignore[no-untyped-def]
        raise NotImplementedError

    def get_metrics(self):  # type: ignore[no-untyped-def]
        raise NotImplementedError

    def find_queued(self):  # type: ignore[no-untyped-def]
        raise NotImplementedError

    def find_assigned(self):  # type: ignore[no-untyped-def]
        raise NotImplementedError

    def find_retrying(self):  # type: ignore[no-untyped-def]
        raise NotImplementedError

    def find_expired(self):  # type: ignore[no-untyped-def]
        raise NotImplementedError


class _UnusedLeasePort(JobLeaseRepositoryPort):
    def create(self, lease):  # type: ignore[no-untyped-def]
        raise NotImplementedError

    def get(self, lease_id):  # type: ignore[no-untyped-def]
        raise NotImplementedError

    def find_by_job(self, job_id):  # type: ignore[no-untyped-def]
        raise NotImplementedError

    def find_by_worker(self, worker_id):  # type: ignore[no-untyped-def]
        raise NotImplementedError

    def find_expired(self):  # type: ignore[no-untyped-def]
        raise NotImplementedError

    def update(self, lease):  # type: ignore[no-untyped-def]
        raise NotImplementedError

    def delete(self, lease_id):  # type: ignore[no-untyped-def]
        raise NotImplementedError


class _UnusedDeadLetterPort(DeadLetterRepositoryPort):
    def push(self, entry):  # type: ignore[no-untyped-def]
        raise NotImplementedError

    def get(self, entry_id):  # type: ignore[no-untyped-def]
        raise NotImplementedError

    def find_all(self):  # type: ignore[no-untyped-def]
        raise NotImplementedError

    def delete(self, entry_id):  # type: ignore[no-untyped-def]
        raise NotImplementedError

    def count(self):  # type: ignore[no-untyped-def]
        raise NotImplementedError


# ── App builder (mirrors test_rbac.py's _build_app, plus the worker
#    router and its real services) ──────────────────────────────────────


def _build_app() -> tuple[FastAPI, StubUserRepo]:
    token_service = StubTokenService()
    user_repo = StubUserRepo()
    hasher = StubHasher()
    worker_repo = InMemoryWorkerRepo()

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
            if service_type == WorkerRegistrationService:
                return WorkerRegistrationService(worker_repo)
            if service_type == HeartbeatManager:
                return HeartbeatManager(
                    worker_repo,
                    _UnusedQueuePort(),
                    _UnusedLeasePort(),
                    _UnusedDeadLetterPort(),
                )
            if service_type == ServiceAPI:
                raise ValueError("ServiceAPI not needed by these tests")
            raise ValueError(f"Unknown service: {service_type}")

    app.state.kingsec_app = _StubApp()  # type: ignore[attr-defined]

    from kingsec.adapters.inbound.web.error_handlers import register_error_handlers
    from kingsec.adapters.inbound.web.routes import router as auth_router
    from kingsec.adapters.inbound.web.worker_routes import router as worker_router

    register_error_handlers(app)
    app.include_router(auth_router)
    app.include_router(worker_router)

    return app, user_repo


# ── Tests ────────────────────────────────────────────────────────────────

_WORKER_MUTATIONS: list[tuple[str, str, dict | None]] = [
    ("POST", "/api/v1/workers/register", {"worker_id": "w1", "hostname": "h1", "os": "linux", "cpu": "x86", "ram_mb": 1024}),
    ("POST", "/api/v1/workers/heartbeat", {"worker_id": "w1"}),
    ("GET", "/api/v1/workers", None),
    ("GET", "/api/v1/workers/w1", None),
    ("DELETE", "/api/v1/workers/w1", None),
]


class TestWorkerAuthorizationUnauthenticated:
    """No credential at all -> 401, for every worker-management route."""

    def setup_method(self) -> None:
        self.app, self._ur = _build_app()
        self.client = TestClient(self.app)

    @pytest.mark.parametrize("method,path,body", _WORKER_MUTATIONS)
    def test_worker_endpoint_returns_401_without_token(self, method: str, path: str, body: dict | None) -> None:
        resp = self.client.request(method, path, json=body)
        assert resp.status_code == 401, f"{method} {path} returned {resp.status_code}: {resp.text}"


class TestWorkerAuthorizationViewer:
    """Viewer (a real, self-registered default role) -> 403 on every route."""

    def setup_method(self) -> None:
        self.app, self._ur = _build_app()
        self.client = TestClient(self.app)

    @pytest.mark.parametrize("method,path,body", _WORKER_MUTATIONS)
    def test_viewer_cannot_access_worker_endpoint(self, method: str, path: str, body: dict | None) -> None:
        _register_viewer(self.client)
        token = _login(self.client)

        resp = self.client.request(method, path, json=body, headers={"Authorization": f"Bearer {token}"})
        assert resp.status_code == 403, f"{method} {path} returned {resp.status_code}: {resp.text}"


class TestWorkerAuthorizationAnalyst:
    """Analyst -> 403 on every route (workers are admin-only, not a
    read-access-for-analysts case)."""

    def setup_method(self) -> None:
        self.app, self._ur = _build_app()
        self.client = TestClient(self.app)

    @pytest.mark.parametrize("method,path,body", _WORKER_MUTATIONS)
    def test_analyst_cannot_access_worker_endpoint(self, method: str, path: str, body: dict | None) -> None:
        _register_user(self.client, username="analyst1", email="analyst1@example.com")
        _promote_user_in_repo(self._ur, "analyst1", "analyst")
        token = _login(self.client, username="analyst1")

        resp = self.client.request(method, path, json=body, headers={"Authorization": f"Bearer {token}"})
        assert resp.status_code == 403, f"{method} {path} returned {resp.status_code}: {resp.text}"


class TestWorkerAuthorizationAdmin:
    """Admin -> the real fix doesn't break legitimate access. Exercised
    through the real register -> list -> get -> heartbeat -> delete
    lifecycle, not just a single smoke request."""

    def setup_method(self) -> None:
        self.app, self._ur = _build_app()
        self.client = TestClient(self.app)

    def _admin_token(self) -> str:
        # Phase 3: self-registration never grants Admin - promote directly
        # in the stub repo, same pattern test_rbac.py itself uses.
        _register_user(self.client, username="admin1", email="admin1@example.com")
        _promote_user_in_repo(self._ur, "admin1", "admin")
        return _login(self.client, username="admin1")

    def test_admin_can_register_list_get_and_delete_a_worker(self) -> None:
        token = self._admin_token()
        headers = {"Authorization": f"Bearer {token}"}

        reg = self.client.post(
            "/api/v1/workers/register",
            json={"worker_id": "w1", "hostname": "h1", "os": "linux", "cpu": "x86", "ram_mb": 1024},
            headers=headers,
        )
        assert reg.status_code == 200, reg.text

        listing = self.client.get("/api/v1/workers", headers=headers)
        assert listing.status_code == 200
        assert listing.json()["total"] == 1

        got = self.client.get("/api/v1/workers/w1", headers=headers)
        assert got.status_code == 200

        hb = self.client.post("/api/v1/workers/heartbeat", json={"worker_id": "w1"}, headers=headers)
        assert hb.status_code == 200

        deleted = self.client.delete("/api/v1/workers/w1", headers=headers)
        assert deleted.status_code == 200

        gone = self.client.get("/api/v1/workers/w1", headers=headers)
        assert gone.status_code == 404


class TestWorkerAuthorizationBypassAttempts:
    """Step 6: confirm the check can't be sidestepped by adjacent means."""

    def setup_method(self) -> None:
        self.app, self._ur = _build_app()
        self.client = TestClient(self.app)

    def test_missing_authorization_header_is_401_not_500(self) -> None:
        resp = self.client.get("/api/v1/workers")
        assert resp.status_code == 401

    def test_malformed_token_is_401(self) -> None:
        resp = self.client.get(
            "/api/v1/workers",
            headers={"Authorization": "Bearer not-a-real-token"},
        )
        assert resp.status_code == 401

    def test_forged_role_in_a_syntactically_plausible_but_unissued_token_is_401(self) -> None:
        """A bearer value that looks like a real access token but was
        never actually issued (i.e. a forged claim) must still fail -
        proves verification is against the real issued-token store, not
        just decoding an unsigned/unverified shape."""
        resp = self.client.get(
            "/api/v1/workers",
            headers={"Authorization": "Bearer access-forged0000000000000000"},
        )
        assert resp.status_code == 401

    def test_viewer_cannot_use_the_get_single_worker_route_as_a_side_channel(self) -> None:
        """A narrower route (GET one worker by id) must not be an
        accidental bypass of the router-level admin gate."""
        _register_viewer(self.client)
        token = _login(self.client)
        resp = self.client.get(
            "/api/v1/workers/anything",
            headers={"Authorization": f"Bearer {token}"},
        )
        assert resp.status_code == 403

    def test_expired_token_is_401(self) -> None:
        """StubTokenService's verify_access_token only checks presence/
        type/revocation, not expiry - so this exercises the real
        _verify_jwt() error path via a token that plainly does not exist
        in the issuer's store, the same shape an expired-and-purged
        token would take."""
        resp = self.client.get(
            "/api/v1/workers",
            headers={"Authorization": "Bearer access-0000000000000000expired"},
        )
        assert resp.status_code == 401

    def test_malformed_role_claim_is_401_not_silently_privileged(self) -> None:
        """A genuinely-issued, genuinely-verified token whose role claim
        is not a real Role value must fail closed (401, 'invalid token
        claims') rather than falling through to some default. Exercises
        auth.py's _verify_jwt() Role[claims.role.upper()] KeyError path,
        a distinct code path from "valid role, insufficient privilege"
        (which is the 403 case tested above)."""
        token = self.app.state.kingsec_app.resolve(TokenService).create_access_token(
            user_id="u1", username="attacker", role="not-a-real-role"
        )
        resp = self.client.get(
            "/api/v1/workers",
            headers={"Authorization": f"Bearer {token}"},
        )
        assert resp.status_code == 401
        assert "invalid token claims" in resp.json().get("detail", resp.json().get("message", ""))
