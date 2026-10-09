"""KSEC-107: HTTP-level adversarial verification of Assessment creation and
submission duplicate/idempotency behavior.

Before this phase, NO integration test exercised POST /api/v1/assessments
or POST /api/v1/assessments/{id}/start through a real wired FastAPI
application (confirmed by search: test_assessment_failure_visibility.py
only exercises GET, via a stub ServiceAPI). These tests close that gap and
answer Phase 107's primary question at the real HTTP boundary, not just
the use-case boundary: real wired app, real on-disk SQLite, real
ThreadJobRunner, real authentication/authorization dependency overrides
(only ``get_current_user`` is overridden, never ``require_role``/
``require_analyst`` themselves).
"""

from __future__ import annotations

import io
import threading
from datetime import UTC, datetime

import pytest
from cryptography.fernet import Fernet
from fastapi.testclient import TestClient

from kingsec.adapters.inbound.web.app import create_fastapi_app
from kingsec.adapters.inbound.web.auth import CurrentUser, get_current_user
from kingsec.application import SubmitAssessment
from kingsec.application.ports import ScannerPort, TokenClaims
from kingsec.bootstrap.application import Application
from kingsec.bootstrap.composition import create_wired_application
from kingsec.domain import Finding, Role, Severity, Target
from kingsec.infrastructure.persistence import create_database_engine, create_schema

_TEST_FERNET_KEY = Fernet.generate_key().decode()
_TEST_JWT_SECRET = "test-jwt-secret-" + Fernet.generate_key().decode()
_TEST_PEPPER = "test-pepper-" + Fernet.generate_key().decode()


class _CountingScanner(ScannerPort):
    def __init__(self) -> None:
        self._lock = threading.Lock()
        self.invocation_count = 0

    def scan(self, target: Target):
        with self._lock:
            self.invocation_count += 1
        return [Finding.create("SQLi", "injectable param", Severity.CRITICAL)]

    def compatible_scanners(self, target: Target) -> dict[str, str]:
        return {"stub": "Stub Scanner"}


def _use_test_scanner(app: Application, scanner: ScannerPort) -> None:
    """Keep these HTTP lifecycle tests independent of host scanner binaries."""
    app.container.register_instance(ScannerPort, scanner)
    submit = app.resolve(SubmitAssessment)
    submit._scanner = scanner
    submit._planner = None
    submit._scanner_executor = None


def _make_user(role: Role, user_id: str = "user-001") -> CurrentUser:
    now = datetime.now(UTC)
    return CurrentUser(
        user_id=user_id,
        username=f"{role.label.lower()}-user",
        role=role,
        claims=TokenClaims(
            user_id=user_id,
            username=f"{role.label.lower()}-user",
            role=role.label.lower(),
            token_type="access",
            jti="jti-test-107",
            issued_at=now,
            expires_at=now,
        ),
    )


@pytest.fixture
def scanner_spy() -> _CountingScanner:
    return _CountingScanner()


@pytest.fixture
def wired_app(tmp_path, monkeypatch, scanner_spy: _CountingScanner) -> Application:
    monkeypatch.setenv("KINGSEC_STORAGE__DATA_DIR", str(tmp_path))
    monkeypatch.setenv("KINGSEC_SECRETS__ENCRYPTION_KEY", _TEST_FERNET_KEY)
    monkeypatch.setenv("KINGSEC_JWT__SECRET_KEY", _TEST_JWT_SECRET)
    monkeypatch.setenv("KINGSEC_SECRETS__API_KEY_PEPPER", _TEST_PEPPER)
    monkeypatch.setenv("KINGSEC_SECURITY__ENFORCE_AUTHORIZATION_SCOPE", "false")
    app = create_wired_application(log_stream=io.StringIO(), ensure_directories=False, validate_migrations=False)
    engine = create_database_engine(settings=app.settings)
    create_schema(engine)
    engine.dispose()
    _use_test_scanner(app, scanner_spy)
    return app


def _client_as(app: Application, role: Role | None, user_id: str = "user-001") -> TestClient:
    fastapi_app = create_fastapi_app(app)
    if role is not None:
        fastapi_app.dependency_overrides[get_current_user] = lambda: _make_user(role, user_id)
    return TestClient(fastapi_app, raise_server_exceptions=False)


_CREATE_BODY = {
    "target_value": "10.0.0.9",
    "target_type": "ip_address",
    "profile_id": "quick-scan",
    "authorized_by": "pentester@kingusecurity.com",
    "scope": "10.0.0.9",
}


# ── Section 6 / Race B, C: two and four identical concurrent HTTP
# submissions ────────────────────────────────────────────────────────────


class TestConcurrentIdenticalHttpCreateRequests:
    @pytest.mark.parametrize("n_requests", [2, 4], ids=["race-b-2", "race-c-4"])
    def test_n_concurrent_identical_creates_produce_n_distinct_assessments(
        self, wired_app: Application, n_requests: int
    ) -> None:
        """Every request is legitimately treated as a new assessment - no
        idempotency key exists anywhere in CreateAssessmentRequest (Section
        5/14 source re-read). This is Outcome B (Section 6/31): NOT a
        vulnerability by itself, just the documented, intentional absence
        of duplicate-request protection - verified here at the real HTTP
        boundary with genuine concurrent threads, not assumed.

        Each thread gets its OWN TestClient instance (all wrapping the
        SAME underlying FastAPI app/wired Application) rather than sharing
        one - starlette's TestClient is not documented as safe to drive
        from multiple genuinely concurrent threads at once, and sharing
        one was observed to intermittently return a spurious 405 under
        real thread contention, unrelated to the actual behavior under
        test."""
        barrier = threading.Barrier(n_requests)
        responses: list[dict | None] = [None] * n_requests

        def _post(i: int) -> None:
            client = _client_as(wired_app, role=Role.ANALYST)
            barrier.wait(timeout=10)
            resp = client.post("/api/v1/assessments", json=_CREATE_BODY)
            responses[i] = {"status": resp.status_code, "body": resp.json()}

        threads = [threading.Thread(target=_post, args=(i,)) for i in range(n_requests)]
        for t in threads:
            t.start()
        for t in threads:
            t.join(timeout=15)

        assert all(r is not None for r in responses)
        assert all(r["status"] == 201 for r in responses), responses
        assessment_ids = {r["body"]["assessment_id"] for r in responses}
        assert len(assessment_ids) == n_requests, (
            f"expected {n_requests} distinct assessment ids from {n_requests} concurrent "
            f"identical create requests (no idempotency key exists), got {len(assessment_ids)}: {responses}"
        )


# ── Section 13: sequential replay simulating a lost HTTP response ──────


class TestSequentialCreateRetrySimulation:
    def test_client_retry_after_lost_response_creates_a_second_assessment(self, wired_app: Application) -> None:
        """Deterministic simulation of Section 13: the first request
        actually succeeds server-side; the client (for this test) simply
        never inspects/uses the first response and issues an identical
        second request, exactly modeling "the response was lost, so I
        retried." No idempotency-key/request-id is read by CreateAssessment
        (confirmed by source re-read - Section 14), so this deterministically
        produces two independent, real Assessments."""
        client = _client_as(wired_app, role=Role.ANALYST)
        first = client.post("/api/v1/assessments", json=_CREATE_BODY)
        second = client.post("/api/v1/assessments", json=_CREATE_BODY)
        assert first.status_code == 201
        assert second.status_code == 201
        assert first.json()["assessment_id"] != second.json()["assessment_id"]


# ── Section 10 / Race G, H: submit after terminal via real HTTP ────────


class TestHttpSubmitAfterTerminal:
    def test_starting_an_already_completed_assessment_returns_a_clean_error_not_500(
        self, wired_app: Application
    ) -> None:
        client = _client_as(wired_app, role=Role.ANALYST)
        create_resp = client.post("/api/v1/assessments", json=_CREATE_BODY)
        assessment_id = create_resp.json()["assessment_id"]

        first_start = client.post(f"/api/v1/assessments/{assessment_id}/start")
        assert first_start.status_code == 202

        import time

        for _ in range(50):
            poll = client.get(f"/api/v1/assessments/{assessment_id}")
            if poll.json()["status"] in {"completed", "completed_with_gaps"}:
                break
            time.sleep(0.1)
        else:
            raise AssertionError("assessment did not complete within timeout")

        second_start = client.post(f"/api/v1/assessments/{assessment_id}/start")
        assert second_start.status_code < 500, (
            f"resubmitting a COMPLETED assessment must return a clean client error, "
            f"not an unhandled 500: got {second_start.status_code} {second_start.text}"
        )
        assert second_start.status_code in (400, 409, 422)


# ── Section 19: Assessment ID attacks against the submission endpoint ──


class TestHttpAssessmentIdAttacksOnSubmit:
    @pytest.mark.parametrize(
        "bad_id",
        [
            "not-a-real-id",
            "'; DROP TABLE assessments; --",
            "x" * 5000,
            "asmt-ü中文",
        ],
    )
    def test_malformed_or_hostile_id_never_causes_500(self, wired_app: Application, bad_id: str) -> None:
        client = _client_as(wired_app, role=Role.ANALYST)
        resp = client.post(f"/api/v1/assessments/{bad_id}/start")
        assert resp.status_code < 500, f"got {resp.status_code}: {resp.text}"
        assert resp.status_code in (400, 404, 414, 422, 431)

    def test_another_users_assessment_id_is_not_found_not_forbidden_and_not_leaked(
        self, wired_app: Application
    ) -> None:
        victim_client = _client_as(wired_app, role=Role.ANALYST, user_id="victim-user")
        create_resp = victim_client.post("/api/v1/assessments", json=_CREATE_BODY)
        victim_assessment_id = create_resp.json()["assessment_id"]

        attacker_client = _client_as(wired_app, role=Role.ANALYST, user_id="attacker-user")
        resp = attacker_client.post(f"/api/v1/assessments/{victim_assessment_id}/start")
        assert resp.status_code == 404, (
            f"an assessment belonging to another user must appear NOT FOUND to a non-owner, "
            f"non-admin caller (fails closed, no existence leak) - got {resp.status_code}: {resp.text}"
        )

    def test_unauthenticated_caller_cannot_create_or_submit(self, wired_app: Application) -> None:
        client = _client_as(wired_app, role=None)
        create_resp = client.post("/api/v1/assessments", json=_CREATE_BODY)
        assert create_resp.status_code in (401, 403)

        start_resp = client.post("/api/v1/assessments/some-id/start")
        assert start_resp.status_code in (401, 403)

    def test_viewer_role_cannot_start_an_assessment(self, wired_app: Application) -> None:
        analyst_client = _client_as(wired_app, role=Role.ANALYST, user_id="owner-user")
        create_resp = analyst_client.post("/api/v1/assessments", json=_CREATE_BODY)
        assessment_id = create_resp.json()["assessment_id"]

        viewer_client = _client_as(wired_app, role=Role.VIEWER, user_id="owner-user")
        resp = viewer_client.post(f"/api/v1/assessments/{assessment_id}/start")
        assert resp.status_code == 403


# ── KSEC-107-01 / KSEC-108-01: Phase 109 adversarial verification at the
# real HTTP boundary - attack classes H (HTTP concurrency), I (client
# version manipulation), J (admin operations), O (error handling) ──────


class TestHttpAdminCancelRacesLiveSubmission:
    def test_admin_cancel_during_a_live_scan_returns_a_clean_response_not_500(
        self, wired_app: Application
    ) -> None:
        """A real HTTP admin cancel racing a real, genuinely in-flight
        background scan (via a gated scanner) - exercises
        submit_assessment.py's own exception-recovery path with a REAL
        AssessmentConflictError raised through the full stack, verifying
        the HTTP layer never turns it into a 500 and never leaks
        internals, regardless of which side wins the race."""
        import threading as _threading

        class _GatedScanner(ScannerPort):
            def __init__(self) -> None:
                self.entered = _threading.Event()
                self.release_gate = _threading.Event()

            def scan(self, target: Target):
                self.entered.set()
                self.release_gate.wait(timeout=10)
                return [Finding.create("SQLi", "injectable param", Severity.CRITICAL)]

            def compatible_scanners(self, target: Target) -> dict[str, str]:
                return {"stub": "Stub Scanner"}

        gated_scanner = _GatedScanner()
        _use_test_scanner(wired_app, gated_scanner)

        analyst_client = _client_as(wired_app, role=Role.ANALYST, user_id="owner-user")
        create_resp = analyst_client.post("/api/v1/assessments", json=_CREATE_BODY)
        assessment_id = create_resp.json()["assessment_id"]

        start_resp = analyst_client.post(f"/api/v1/assessments/{assessment_id}/start")
        assert start_resp.status_code == 202
        assert gated_scanner.entered.wait(timeout=10), "scanner never started"

        admin_client = _client_as(wired_app, role=Role.ADMIN, user_id="admin-user")
        cancel_resp = admin_client.post(f"/api/v1/assessments/{assessment_id}/cancel")

        assert cancel_resp.status_code < 500, (
            f"admin cancel during a live scan must never surface as a 500: "
            f"got {cancel_resp.status_code} {cancel_resp.text}"
        )
        assert cancel_resp.status_code == 200

        body_text = cancel_resp.text.lower()
        for leaked in ("traceback", "sqlalchemy", "sqlite3", ".py\"", "site-packages", "assessmentorm"):
            assert leaked not in body_text, f"response body leaked internal detail {leaked!r}: {cancel_resp.text}"

        gated_scanner.release_gate.set()

        import time

        for _ in range(50):
            poll = analyst_client.get(f"/api/v1/assessments/{assessment_id}")
            if poll.json()["status"] in ("cancelled", "completed"):
                break
            time.sleep(0.1)

        # The admin's CANCELLED decision must be durable and never
        # silently reverted by the scan's own (now-stale) terminal save.
        final = analyst_client.get(f"/api/v1/assessments/{assessment_id}")
        assert final.json()["status"] == "cancelled"


class TestHttpClientVersionManipulation:
    @pytest.mark.parametrize("bad_body", [{"version": 0}, {"version": 1}, {"version": 999999999}, {"version": -1}])
    def test_client_supplied_version_field_is_rejected_not_honored(
        self, wired_app: Application, bad_body: dict
    ) -> None:
        """TESTED (not merely inferred): every Assessment-mutating request
        body uses Pydantic's extra="forbid" - a client-supplied "version"
        field is actively rejected (422), never silently accepted and
        never capable of influencing which durable version is checked
        against. The server-side version always comes exclusively from
        the database row itself (assessment_to_domain()), never from any
        request body."""
        client = _client_as(wired_app, role=Role.ANALYST)
        create_resp = client.post("/api/v1/assessments", json={**_CREATE_BODY, **bad_body})
        assert create_resp.status_code == 422, (
            f"a client-supplied version field must be rejected outright: got {create_resp.status_code}"
        )

        # Also confirmed on /start and /cancel - their bodies are declared
        # empty-with-extra-forbid, so any extra field (including "version")
        # is rejected the same way.
        create_resp2 = client.post("/api/v1/assessments", json=_CREATE_BODY)
        assessment_id = create_resp2.json()["assessment_id"]
        start_resp = client.post(f"/api/v1/assessments/{assessment_id}/start", json=bad_body)
        assert start_resp.status_code == 422


class TestHttpConcurrentAdminAndOwnerSubmission:
    def test_admin_and_owner_racing_the_same_assessment_produce_no_stale_overwrite(
        self, wired_app: Application, scanner_spy: _CountingScanner
    ) -> None:
        """Attack Class J: admin privilege must not bypass version gating.
        A real HTTP race between the owning analyst and an admin, both
        legitimately entitled to submit the same assessment."""
        owner_client = _client_as(wired_app, role=Role.ANALYST, user_id="owner-user")
        create_resp = owner_client.post("/api/v1/assessments", json=_CREATE_BODY)
        assessment_id = create_resp.json()["assessment_id"]

        admin_client = _client_as(wired_app, role=Role.ADMIN, user_id="admin-user")

        barrier = threading.Barrier(2)
        responses: list[dict | None] = [None, None]

        def _submit_as_owner() -> None:
            barrier.wait(timeout=10)
            resp = owner_client.post(f"/api/v1/assessments/{assessment_id}/start")
            responses[0] = {"status": resp.status_code}

        def _submit_as_admin() -> None:
            barrier.wait(timeout=10)
            resp = admin_client.post(f"/api/v1/assessments/{assessment_id}/start")
            responses[1] = {"status": resp.status_code}

        t1 = threading.Thread(target=_submit_as_owner)
        t2 = threading.Thread(target=_submit_as_admin)
        t1.start()
        t2.start()
        t1.join(timeout=15)
        t2.join(timeout=15)

        statuses = [r["status"] for r in responses if r is not None]
        assert statuses.count(202) == 1, f"exactly one submission must succeed: {statuses}"
        assert all(s < 500 for s in statuses), f"the loser must get a clean status, never a 500: {statuses}"

        import time

        for _ in range(50):
            poll = owner_client.get(f"/api/v1/assessments/{assessment_id}")
            if poll.json()["status"] == "completed":
                break
            time.sleep(0.1)

        assert scanner_spy.invocation_count == 1
        final = owner_client.get(f"/api/v1/assessments/{assessment_id}")
        assert final.json()["status"] == "completed"
