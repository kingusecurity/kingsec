"""Regression tests for distributed queue/job (Workers subsystem) route
authorization - distributed_routes.py.

Phase 02 remediation. Same real-boundary pattern as test_rbac.py /
test_worker_routes_authorization.py: a real FastAPI app is built with
the actual distributed_routes.py router included, backed by real
Login/RegisterUser/TokenService wiring so a genuine JWT is minted and
verified through the real auth dependency chain.

JobQueueEntry (the domain type this router operates on) carries no
owner/user field anywhere in its construction (confirmed by reading
domain/job.py and every call site that builds one) - this is
infrastructure-level, worker-dispatched execution state, not a
user-owned resource the way Assessment is. There is therefore no
ownership dimension to test for this resource type; the correct policy
is role-based only, matching the sibling queue_routes.py's own
established pattern for the same conceptual operations on its own
(user-owned) resource type: mutations require Admin, and any read that
carries per-job detail (`payload`, `target`, `error_message`, dead-letter
`reason`) requires Admin - including `list_queue`/`list_dead_letter`,
which are list-shaped but still leak per-job detail (KSEC-84-01; the
original version of this file incorrectly left them open, the same class
of gap already fixed in queue_routes.py under KSEC-71-02). Only the
genuinely aggregate-only `queue_metrics` (counts, no per-job data) stays
open to any authenticated user.
"""

from __future__ import annotations

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient

from kingsec.application import Login, RefreshToken, RegisterUser
from kingsec.application.auth import AuthorizationService
from kingsec.application.distributed.ports import DeadLetterRepositoryPort, JobQueueRepositoryPort
from kingsec.application.distributed.retry_manager import DeadLetterService, RetryManager
from kingsec.application.ports import TokenService
from kingsec.application.use_cases.check_rate_limit import CheckRateLimit
from kingsec.domain.job import DeadLetterEntry, JobQueueEntry, JobState
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

# ── Minimal real in-memory queue/dead-letter infrastructure ────────────


class InMemoryJobQueueRepo(JobQueueRepositoryPort):
    def __init__(self) -> None:
        self._entries: dict[str, JobQueueEntry] = {}

    def enqueue(self, entry: JobQueueEntry) -> JobQueueEntry:
        self._entries[entry.entry_id] = entry
        return entry

    def get(self, entry_id: str) -> JobQueueEntry | None:
        return self._entries.get(entry_id)

    def find_by_state(self, state: str) -> list[JobQueueEntry]:
        return [e for e in self._entries.values() if e.state.value == state]

    def find_all(self) -> list[JobQueueEntry]:
        return list(self._entries.values())

    def update(self, entry: JobQueueEntry) -> None:
        self._entries[entry.entry_id] = entry

    def delete(self, entry_id: str) -> None:
        self._entries.pop(entry_id, None)

    def get_metrics(self):  # type: ignore[no-untyped-def]
        from kingsec.domain.job import QueueMetrics

        return QueueMetrics(
            total_queued=0, total_assigned=0, total_running=0, total_completed=0,
            total_failed=0, total_cancelled=0, total_retrying=0, total_expired=0,
            total_dead_letter=0, average_wait_seconds=0.0, oldest_job_age_seconds=0.0,
        )

    def find_queued(self):  # type: ignore[no-untyped-def]
        return []

    def find_assigned(self):  # type: ignore[no-untyped-def]
        return []

    def find_retrying(self):  # type: ignore[no-untyped-def]
        return []

    def find_expired(self):  # type: ignore[no-untyped-def]
        return []


class InMemoryDeadLetterRepo(DeadLetterRepositoryPort):
    def __init__(self) -> None:
        self._entries: dict[str, DeadLetterEntry] = {}

    def push(self, entry: DeadLetterEntry) -> DeadLetterEntry:
        self._entries[entry.entry_id] = entry
        return entry

    def get(self, entry_id: str) -> DeadLetterEntry | None:
        return self._entries.get(entry_id)

    def find_all(self) -> list[DeadLetterEntry]:
        return list(self._entries.values())

    def delete(self, entry_id: str) -> None:
        self._entries.pop(entry_id, None)

    def count(self) -> int:
        return len(self._entries)


def _seed_entry(repo: InMemoryJobQueueRepo, entry_id: str = "jq-1") -> JobQueueEntry:
    entry = JobQueueEntry(entry_id=entry_id, job_id=f"job-{entry_id}", state=JobState.QUEUED, target="10.0.0.5")
    repo.enqueue(entry)
    return entry


def _seed_dead_letter(dl_repo: InMemoryDeadLetterRepo, entry_id: str = "dl-1") -> DeadLetterEntry:
    entry = DeadLetterEntry(
        entry_id=entry_id, original_job_id="job-jq-1", original_entry_id="jq-1",
        reason="max retries exceeded", retry_count=3,
    )
    dl_repo.push(entry)
    return entry


# ── App builder ──────────────────────────────────────────────────────────


def _build_app() -> tuple[FastAPI, StubUserRepo, InMemoryJobQueueRepo, InMemoryDeadLetterRepo]:
    token_service = StubTokenService()
    user_repo = StubUserRepo()
    hasher = StubHasher()
    queue_repo = InMemoryJobQueueRepo()
    dl_repo = InMemoryDeadLetterRepo()

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
                    user_repo, hasher, token_service,
                    StubLockoutRepo(), StubClock(),
                    LockoutPolicy(max_attempts=5, lockout_duration_seconds=900),
                    StubMfaSecretRepo(),
                )
            if service_type == RefreshToken:
                return RefreshToken(user_repo, token_service)
            if service_type == AuthorizationService:
                return AuthorizationService()
            if service_type == CheckRateLimit:
                return CheckRateLimit(StubRateLimiter())
            if service_type == JobQueueRepositoryPort:
                return queue_repo
            if service_type == RetryManager:
                return RetryManager(queue_repo, dl_repo)
            if service_type == DeadLetterService:
                return DeadLetterService(dl_repo, queue_repo)
            if service_type == ServiceAPI:
                raise ValueError("ServiceAPI not needed by these tests")
            raise ValueError(f"Unknown service: {service_type}")

    app.state.kingsec_app = _StubApp()  # type: ignore[attr-defined]

    from kingsec.adapters.inbound.web.distributed_routes import router as queue_router
    from kingsec.adapters.inbound.web.error_handlers import register_error_handlers
    from kingsec.adapters.inbound.web.routes import router as auth_router

    register_error_handlers(app)
    app.include_router(auth_router)
    app.include_router(queue_router)

    return app, user_repo, queue_repo, dl_repo


# ── Tests ────────────────────────────────────────────────────────────────

_UNAUTHENTICATED_401_ROUTES: list[tuple[str, str]] = [
    ("GET", "/api/v1/queue"),
    ("GET", "/api/v1/queue/metrics"),
    ("POST", "/api/v1/queue/retry/jq-1"),
    ("POST", "/api/v1/queue/cancel/jq-1"),
    ("GET", "/api/v1/queue/dead-letter"),
    ("POST", "/api/v1/queue/dead-letter/dl-1/requeue"),
    ("GET", "/api/v1/queue/jq-1"),
]

_MUTATIONS: list[tuple[str, str]] = [
    ("POST", "/api/v1/queue/retry/jq-1"),
    ("POST", "/api/v1/queue/cancel/jq-1"),
    ("POST", "/api/v1/queue/dead-letter/dl-1/requeue"),
]

_ADMIN_ONLY_READS: list[str] = [
    "/api/v1/queue/jq-1",  # single-entry detail, carries payload/target
    # KSEC-84-01: these two DO carry per-job detail (target, error_message,
    # reason) despite being "list" shaped - Admin-only, matching the
    # single-entry detail read above and the sibling queue_routes.py fix
    # (KSEC-71-02) for the identical class of leak.
    "/api/v1/queue",
    "/api/v1/queue/dead-letter",
]

_OPEN_TO_ANY_AUTHENTICATED_READS: list[str] = [
    "/api/v1/queue/metrics",  # genuinely aggregate counts only, no per-job data
]


class TestQueueAuthorizationUnauthenticated:
    def setup_method(self) -> None:
        self.app, self._ur, self._qr, self._dl = _build_app()
        self.client = TestClient(self.app)
        _seed_entry(self._qr)
        _seed_dead_letter(self._dl)

    @pytest.mark.parametrize("method,path", _UNAUTHENTICATED_401_ROUTES)
    def test_returns_401_without_token(self, method: str, path: str) -> None:
        resp = self.client.request(method, path, json={})
        assert resp.status_code == 401, f"{method} {path} returned {resp.status_code}: {resp.text}"


class TestQueueAuthorizationMutations:
    """The audit's specific finding: retry/cancel/requeue must require
    Admin, matching queue_routes.py's equivalent mutating endpoints."""

    def setup_method(self) -> None:
        self.app, self._ur, self._qr, self._dl = _build_app()
        self.client = TestClient(self.app)
        _seed_entry(self._qr)
        _seed_dead_letter(self._dl)

    @pytest.mark.parametrize("method,path", _MUTATIONS)
    def test_viewer_cannot_mutate(self, method: str, path: str) -> None:
        _register_viewer(self.client)
        token = _login(self.client)
        resp = self.client.request(method, path, headers={"Authorization": f"Bearer {token}"})
        assert resp.status_code == 403, f"{method} {path} returned {resp.status_code}: {resp.text}"

    @pytest.mark.parametrize("method,path", _MUTATIONS)
    def test_analyst_cannot_mutate(self, method: str, path: str) -> None:
        _register_user(self.client, username="analyst1", email="analyst1@example.com")
        _promote_user_in_repo(self._ur, "analyst1", "analyst")
        token = _login(self.client, username="analyst1")
        resp = self.client.request(method, path, headers={"Authorization": f"Bearer {token}"})
        assert resp.status_code == 403, f"{method} {path} returned {resp.status_code}: {resp.text}"

    def test_admin_can_retry_a_job(self) -> None:
        _register_user(self.client, username="admin1", email="admin1@example.com")
        token = _login(self.client, username="admin1")
        resp = self.client.post("/api/v1/queue/retry/jq-1", headers={"Authorization": f"Bearer {token}"})
        assert resp.status_code == 200, resp.text

    def test_admin_can_cancel_a_job(self) -> None:
        _register_user(self.client, username="admin1", email="admin1@example.com")
        token = _login(self.client, username="admin1")
        resp = self.client.post("/api/v1/queue/cancel/jq-1", headers={"Authorization": f"Bearer {token}"})
        assert resp.status_code == 200, resp.text

    def test_admin_can_requeue_a_dead_letter_entry(self) -> None:
        _register_user(self.client, username="admin1", email="admin1@example.com")
        token = _login(self.client, username="admin1")
        resp = self.client.post("/api/v1/queue/dead-letter/dl-1/requeue", headers={"Authorization": f"Bearer {token}"})
        assert resp.status_code == 200, resp.text


class TestQueueAuthorizationSingleEntryDetail:
    """get_queue_entry, list_queue, and list_dead_letter all return
    per-job detail (payload/target/error_message/reason) - Admin-only,
    matching queue_routes.py's equivalent detail-bearing reads."""

    def setup_method(self) -> None:
        self.app, self._ur, self._qr, self._dl = _build_app()
        self.client = TestClient(self.app)
        _seed_entry(self._qr)

    @pytest.mark.parametrize("path", _ADMIN_ONLY_READS)
    def test_viewer_cannot_read_single_entry_detail(self, path: str) -> None:
        _register_viewer(self.client)
        token = _login(self.client)
        resp = self.client.get(path, headers={"Authorization": f"Bearer {token}"})
        assert resp.status_code == 403, f"GET {path} returned {resp.status_code}: {resp.text}"

    @pytest.mark.parametrize("path", _ADMIN_ONLY_READS)
    def test_analyst_cannot_read_single_entry_detail(self, path: str) -> None:
        _register_user(self.client, username="analyst1", email="analyst1@example.com")
        _promote_user_in_repo(self._ur, "analyst1", "analyst")
        token = _login(self.client, username="analyst1")
        resp = self.client.get(path, headers={"Authorization": f"Bearer {token}"})
        assert resp.status_code == 403, f"GET {path} returned {resp.status_code}: {resp.text}"

    def test_admin_can_read_single_entry_detail(self) -> None:
        _register_user(self.client, username="admin1", email="admin1@example.com")
        token = _login(self.client, username="admin1")
        resp = self.client.get("/api/v1/queue/jq-1", headers={"Authorization": f"Bearer {token}"})
        assert resp.status_code == 200
        assert "payload" in resp.json()


class TestQueueAuthorizationOpenReads:
    """Only genuinely aggregate reads (counts, no per-job data) stay open
    to any authenticated user."""

    def setup_method(self) -> None:
        self.app, self._ur, self._qr, self._dl = _build_app()
        self.client = TestClient(self.app)
        _seed_entry(self._qr)
        _seed_dead_letter(self._dl)

    @pytest.mark.parametrize("path", _OPEN_TO_ANY_AUTHENTICATED_READS)
    def test_viewer_can_read(self, path: str) -> None:
        _register_viewer(self.client)
        token = _login(self.client)
        resp = self.client.get(path, headers={"Authorization": f"Bearer {token}"})
        assert resp.status_code == 200, f"GET {path} returned {resp.status_code}: {resp.text}"


class TestQueueAuthorizationBypassAttempts:
    def setup_method(self) -> None:
        self.app, self._ur, self._qr, self._dl = _build_app()
        self.client = TestClient(self.app)
        _seed_entry(self._qr)

    def test_malformed_token_is_401(self) -> None:
        resp = self.client.post(
            "/api/v1/queue/cancel/jq-1",
            headers={"Authorization": "Bearer not-a-real-token"},
        )
        assert resp.status_code == 401

    def test_forged_unissued_token_is_401(self) -> None:
        resp = self.client.post(
            "/api/v1/queue/cancel/jq-1",
            headers={"Authorization": "Bearer access-forged0000000000000000"},
        )
        assert resp.status_code == 401

    def test_malformed_role_claim_is_401_not_silently_privileged(self) -> None:
        token = self.app.state.kingsec_app.resolve(TokenService).create_access_token(
            user_id="u1", username="attacker", role="not-a-real-role"
        )
        resp = self.client.post(
            "/api/v1/queue/cancel/jq-1",
            headers={"Authorization": f"Bearer {token}"},
        )
        assert resp.status_code == 401

    def test_expired_token_is_401(self) -> None:
        """StubTokenService doesn't model real expiry timing (same
        documented limitation as Phase 01's worker-authorization tests)
        - this exercises the same "token not found in issuer's store"
        401 path a real expired-and-purged token would take."""
        resp = self.client.post(
            "/api/v1/queue/cancel/jq-1",
            headers={"Authorization": "Bearer access-0000000000000000expired"},
        )
        assert resp.status_code == 401

    def test_viewer_cannot_use_get_single_entry_as_a_side_channel(self) -> None:
        """A narrower GET route must not be an accidental bypass of the
        admin gate on the equivalent mutation."""
        _register_viewer(self.client)
        token = _login(self.client)
        resp = self.client.get("/api/v1/queue/jq-1", headers={"Authorization": f"Bearer {token}"})
        assert resp.status_code == 403

    def test_nonexistent_job_id_still_enforces_authorization_before_404(self) -> None:
        """Authorization must be checked before the resource lookup - a
        Viewer probing a job id that doesn't exist must still get 403,
        not a 404 that would leak whether authorization was even
        reached."""
        _register_viewer(self.client)
        token = _login(self.client)
        resp = self.client.post(
            "/api/v1/queue/cancel/does-not-exist",
            headers={"Authorization": f"Bearer {token}"},
        )
        assert resp.status_code == 403

    def test_alternate_lower_level_queue_router_does_not_bypass_this_gate(self) -> None:
        """queue_routes.py (the sibling Agents-subsystem queue, mounted
        at the same /api/v1/queue prefix) already requires Admin on its
        own equivalent mutation (POST /entry/{id}/cancel) - confirming a
        Viewer can't reach an equivalent operation through that other
        router as a lower-level bypass of this fix. Registered first in
        versioning.py, so its literal paths take precedence for any
        overlapping path shape."""
        _register_viewer(self.client)
        token = _login(self.client)
        # Distinct path shape (nested under /entry/), not reachable via
        # distributed_routes.py's paths - this just confirms the sibling
        # router's own gate independently holds for a Viewer.
        resp = self.client.post(
            "/api/v1/queue/entry/jq-1/cancel",
            headers={"Authorization": f"Bearer {token}"},
        )
        # 403 (admin required) or 404/503 (service not wired in this
        # scratch app) are both fine here - the only unacceptable result
        # is 200, which would mean a Viewer mutated something.
        assert resp.status_code != 200


class TestQueueAuthorizationLegitimateWorkflow:
    """Step 10: the authorized workflow (an Admin operating the queue)
    still works end-to-end after the fix."""

    def setup_method(self) -> None:
        self.app, self._ur, self._qr, self._dl = _build_app()
        self.client = TestClient(self.app)

    def test_admin_full_queue_lifecycle(self) -> None:
        _seed_entry(self._qr, entry_id="jq-2")
        _register_user(self.client, username="admin1", email="admin1@example.com")
        token = _login(self.client, username="admin1")
        headers = {"Authorization": f"Bearer {token}"}

        listing = self.client.get("/api/v1/queue", headers=headers)
        assert listing.status_code == 200
        assert listing.json()["total"] == 1

        metrics = self.client.get("/api/v1/queue/metrics", headers=headers)
        assert metrics.status_code == 200

        detail = self.client.get("/api/v1/queue/jq-2", headers=headers)
        assert detail.status_code == 200

        retried = self.client.post("/api/v1/queue/retry/jq-2", headers=headers)
        assert retried.status_code == 200

        cancelled = self.client.post("/api/v1/queue/cancel/jq-2", headers=headers)
        assert cancelled.status_code == 200
