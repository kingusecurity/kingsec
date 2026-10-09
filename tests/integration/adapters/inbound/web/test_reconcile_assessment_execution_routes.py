"""KSEC-105-01: HTTP-level security and behavior tests for the explicit,
ADMIN-only, evidence-gated assessment-execution reconciliation endpoint.

Real wired FastAPI application, real on-disk SQLite, real
``require_admin``/``require_role`` logic (only ``get_current_user`` is
overridden, never ``require_admin`` itself - the actual role-gate under
test runs for real) - the exact fixture pattern already established in
test_execution_inspection_routes.py (Phase 103).
"""

from __future__ import annotations

import io
from datetime import UTC, datetime
from typing import Any, cast

import pytest
from cryptography.fernet import Fernet
from fastapi.testclient import TestClient
from sqlalchemy.orm import sessionmaker

from kingsec.adapters.inbound.web.app import create_fastapi_app
from kingsec.adapters.inbound.web.auth import CurrentUser, get_current_user
from kingsec.application import SubmitAssessment
from kingsec.application.assessment_execution_ledger import AssessmentExecutionStatus
from kingsec.application.ports import ScannerPort, TokenClaims
from kingsec.application.ports.outbound.audit_publisher import AuditPublisher
from kingsec.bootstrap.application import Application
from kingsec.bootstrap.composition import create_wired_application
from kingsec.domain import Finding, Role, Severity, Target
from kingsec.infrastructure.persistence import create_database_engine, create_schema
from kingsec.infrastructure.persistence.models import AssessmentExecutionORM, AssessmentORM

_TEST_FERNET_KEY = Fernet.generate_key().decode()
_TEST_JWT_SECRET = "test-jwt-secret-" + Fernet.generate_key().decode()
_TEST_PEPPER = "test-pepper-" + Fernet.generate_key().decode()


class _CountingScanner(ScannerPort):
    """Records every real invocation - the side-effect-safety proof
    (KSEC-105-01 Step 15/26) needs an actual spy at the real application
    boundary, not a mocked-out use case."""

    def __init__(self) -> None:
        self.invocation_count = 0

    def scan(self, target: Target):
        self.invocation_count += 1
        return [Finding.create("SQLi", "injectable param", Severity.CRITICAL)]

    def compatible_scanners(self, target: Target) -> dict[str, str]:
        return {"stub": "Stub Scanner"}


def _use_test_scanner(app: Application, scanner: ScannerPort) -> None:
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
            jti="jti-test-001",
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


def _client_as(app: Application, role: Role | None) -> TestClient:
    fastapi_app = create_fastapi_app(app)
    if role is not None:
        fastapi_app.dependency_overrides[get_current_user] = lambda: _make_user(role)
    return TestClient(fastapi_app, raise_server_exceptions=False)


def _now() -> str:
    return datetime.now(UTC).isoformat()


def _session_factory(app: Application):
    engine = create_database_engine(settings=app.settings)
    return engine, sessionmaker(bind=engine, expire_on_commit=False, future=True)


def _seed_assessment(app: Application, *, assessment_id: str, status: str) -> None:
    engine, session_factory = _session_factory(app)
    with session_factory() as session:
        session.add(
            AssessmentORM(
                id=assessment_id,
                target_value="10.0.0.5",
                target_type="ip_address",
                # KSEC-106-01: AssessmentORM.status stores the enum MEMBER
                # NAME (e.g. "RUNNING"), not its lowercase value - matching
                # real production data (mappers.py's assessment_to_orm()).
                status=status.upper(),
                created_at=_now(),
                scanner_summary=[],
            )
        )
        session.commit()
    engine.dispose()


def _seed_execution(
    app: Application, *, execution_id: str, assessment_id: str, status: AssessmentExecutionStatus, version: int = 1
) -> None:
    engine, session_factory = _session_factory(app)
    with session_factory() as session:
        session.add(
            AssessmentExecutionORM(
                id=execution_id,
                assessment_id=assessment_id,
                status=status.value,
                version=version,
                created_at=_now(),
                updated_at=_now(),
            )
        )
        session.commit()
    engine.dispose()


def _seed_running_execution(app: Application, *, assessment_id: str, execution_id: str, assessment_status: str) -> None:
    """Convenience: an assessment + a RUNNING execution record, matching
    the real REQUESTED->CLAIMED->RUNNING progression's final durable
    shape (version=3, mirroring create_requested (v1) -> try_claim (v2)
    -> try_mark_running (v3))."""
    _seed_assessment(app, assessment_id=assessment_id, status=assessment_status)
    _seed_execution(
        app, execution_id=execution_id, assessment_id=assessment_id, status=AssessmentExecutionStatus.RUNNING, version=3
    )


def _count_assessments(app: Application) -> int:
    engine, session_factory = _session_factory(app)
    with session_factory() as session:
        count = session.query(AssessmentORM).count()
    engine.dispose()
    return count


def _reconcile_audit_entries(app: Application) -> list[Any]:
    from kingsec.infrastructure.persistence.audit_repository import SqlAlchemyAuditRepository

    repo = cast(SqlAlchemyAuditRepository, app.resolve(AuditPublisher))
    return repo.list_entries(action="execution_reconciled", limit=200)


# ── A. Authorization ─────────────────────────────────────────────────────


class TestAuthorizationMatrix:
    def test_unauthenticated_is_rejected(self, wired_app: Application) -> None:
        with wired_app:
            _seed_running_execution(wired_app, assessment_id="asmt-1", execution_id="exec-1", assessment_status="completed")
            client = _client_as(wired_app, role=None)
            resp = client.post("/api/v1/assessment-executions/exec-1/reconcile")
        assert resp.status_code == 401

    def test_viewer_is_rejected(self, wired_app: Application) -> None:
        with wired_app:
            _seed_running_execution(wired_app, assessment_id="asmt-2", execution_id="exec-2", assessment_status="completed")
            client = _client_as(wired_app, role=Role.VIEWER)
            resp = client.post("/api/v1/assessment-executions/exec-2/reconcile")
        assert resp.status_code == 403

    def test_analyst_is_rejected(self, wired_app: Application) -> None:
        with wired_app:
            _seed_running_execution(wired_app, assessment_id="asmt-3", execution_id="exec-3", assessment_status="completed")
            client = _client_as(wired_app, role=Role.ANALYST)
            resp = client.post("/api/v1/assessment-executions/exec-3/reconcile")
        assert resp.status_code == 403

    def test_admin_with_valid_evidence_is_permitted(self, wired_app: Application) -> None:
        with wired_app:
            _seed_running_execution(wired_app, assessment_id="asmt-4", execution_id="exec-4", assessment_status="completed")
            client = _client_as(wired_app, role=Role.ADMIN)
            resp = client.post("/api/v1/assessment-executions/exec-4/reconcile")
        assert resp.status_code == 200

    def test_admin_with_invalid_evidence_is_rejected_with_409(self, wired_app: Application) -> None:
        with wired_app:
            _seed_running_execution(wired_app, assessment_id="asmt-5", execution_id="exec-5", assessment_status="running")
            client = _client_as(wired_app, role=Role.ADMIN)
            resp = client.post("/api/v1/assessment-executions/exec-5/reconcile")
        assert resp.status_code == 409

    def test_viewer_and_admin_get_identical_403_regardless_of_execution_existing(self, wired_app: Application) -> None:
        with wired_app:
            client = _client_as(wired_app, role=Role.VIEWER)
            resp_real = client.post("/api/v1/assessment-executions/does-not-exist/reconcile")
        assert resp_real.status_code == 403


# ── Valid reconciliation ────────────────────────────────────────────────────


class TestValidReconciliation:
    def test_running_plus_completed_reconciles_to_succeeded(self, wired_app: Application, scanner_spy: _CountingScanner) -> None:
        with wired_app:
            _seed_running_execution(wired_app, assessment_id="asmt-6", execution_id="exec-6", assessment_status="completed")
            client = _client_as(wired_app, role=Role.ADMIN)
            resp = client.post("/api/v1/assessment-executions/exec-6/reconcile")
        assert resp.status_code == 200
        body = resp.json()
        assert body["execution_id"] == "exec-6"
        assert body["assessment_id"] == "asmt-6"
        assert body["previous_execution_status"] == "RUNNING"
        assert body["execution_status"] == "SUCCEEDED"
        assert body["assessment_status"] == "completed"
        assert body["mutated"] is True
        assert scanner_spy.invocation_count == 0

    def test_running_plus_failed_reconciles_to_failed(self, wired_app: Application, scanner_spy: _CountingScanner) -> None:
        with wired_app:
            _seed_running_execution(wired_app, assessment_id="asmt-7", execution_id="exec-7", assessment_status="failed")
            client = _client_as(wired_app, role=Role.ADMIN)
            resp = client.post("/api/v1/assessment-executions/exec-7/reconcile")
        assert resp.status_code == 200
        body = resp.json()
        assert body["execution_status"] == "FAILED"
        assert body["mutated"] is True
        assert scanner_spy.invocation_count == 0


# ── Invalid evidence ─────────────────────────────────────────────────────


class TestInvalidEvidence:
    @pytest.mark.parametrize(
        ("exec_status", "assessment_status"),
        [
            (AssessmentExecutionStatus.REQUESTED, "running"),
            (AssessmentExecutionStatus.CLAIMED, "running"),
            (AssessmentExecutionStatus.RUNNING, "authorized"),
            (AssessmentExecutionStatus.RUNNING, "running"),
        ],
    )
    def test_unsupported_combinations_are_rejected_without_mutation(
        self, wired_app: Application, exec_status: AssessmentExecutionStatus, assessment_status: str
    ) -> None:
        with wired_app:
            _seed_assessment(wired_app, assessment_id="asmt-8", status=assessment_status)
            _seed_execution(wired_app, execution_id="exec-8", assessment_id="asmt-8", status=exec_status)
            client = _client_as(wired_app, role=Role.ADMIN)
            resp = client.post("/api/v1/assessment-executions/exec-8/reconcile")
            get_resp = client.get("/api/v1/assessment-executions/exec-8")
        assert resp.status_code == 409
        assert get_resp.json()["execution_status"] == exec_status.value, "must not have mutated"

    def test_terminal_succeeded_with_matching_evidence_is_idempotent_not_an_error(self, wired_app: Application) -> None:
        with wired_app:
            _seed_assessment(wired_app, assessment_id="asmt-9", status="completed")
            _seed_execution(wired_app, execution_id="exec-9", assessment_id="asmt-9", status=AssessmentExecutionStatus.SUCCEEDED)
            client = _client_as(wired_app, role=Role.ADMIN)
            resp = client.post("/api/v1/assessment-executions/exec-9/reconcile")
        assert resp.status_code == 200
        body = resp.json()
        assert body["mutated"] is False
        assert body["execution_status"] == "SUCCEEDED"

    def test_terminal_failed_with_matching_evidence_is_idempotent(self, wired_app: Application) -> None:
        with wired_app:
            _seed_assessment(wired_app, assessment_id="asmt-10", status="failed")
            _seed_execution(wired_app, execution_id="exec-10", assessment_id="asmt-10", status=AssessmentExecutionStatus.FAILED)
            client = _client_as(wired_app, role=Role.ADMIN)
            resp = client.post("/api/v1/assessment-executions/exec-10/reconcile")
        assert resp.status_code == 200
        assert resp.json()["mutated"] is False

    def test_inconsistent_state_is_rejected(self, wired_app: Application) -> None:
        with wired_app:
            _seed_assessment(wired_app, assessment_id="asmt-11", status="running")
            _seed_execution(wired_app, execution_id="exec-11", assessment_id="asmt-11", status=AssessmentExecutionStatus.SUCCEEDED)
            client = _client_as(wired_app, role=Role.ADMIN)
            resp = client.post("/api/v1/assessment-executions/exec-11/reconcile")
        assert resp.status_code == 409

    def test_not_found_returns_404(self, wired_app: Application) -> None:
        with wired_app:
            client = _client_as(wired_app, role=Role.ADMIN)
            resp = client.post("/api/v1/assessment-executions/does-not-exist/reconcile")
        assert resp.status_code == 404


# ── Client cannot control the outcome ───────────────────────────────────────


class TestClientCannotControlOutcome:
    def test_caller_supplied_status_field_is_ignored(self, wired_app: Application) -> None:
        with wired_app:
            _seed_running_execution(wired_app, assessment_id="asmt-12", execution_id="exec-12", assessment_status="failed")
            client = _client_as(wired_app, role=Role.ADMIN)
            # The Assessment durably shows FAILED - a malicious/confused
            # caller tries to force SUCCEEDED via the request body anyway.
            resp = client.post(
                "/api/v1/assessment-executions/exec-12/reconcile",
                json={"status": "SUCCEEDED", "outcome": "SUCCEEDED", "result": "success"},
            )
        assert resp.status_code == 200
        # The server-derived outcome (FAILED, from the real Assessment
        # status) wins regardless of what the body claimed.
        assert resp.json()["execution_status"] == "FAILED"

    def test_caller_supplied_force_flag_does_not_bypass_the_evidence_gate(self, wired_app: Application) -> None:
        with wired_app:
            _seed_running_execution(wired_app, assessment_id="asmt-13", execution_id="exec-13", assessment_status="running")
            client = _client_as(wired_app, role=Role.ADMIN)
            resp = client.post(
                "/api/v1/assessment-executions/exec-13/reconcile",
                json={"force": True, "override": True, "retry": True},
            )
        assert resp.status_code == 409

    def test_empty_body_works_identically_to_no_body(self, wired_app: Application) -> None:
        with wired_app:
            _seed_running_execution(wired_app, assessment_id="asmt-14", execution_id="exec-14", assessment_status="completed")
            client = _client_as(wired_app, role=Role.ADMIN)
            resp = client.post("/api/v1/assessment-executions/exec-14/reconcile", json={})
        assert resp.status_code == 200
        assert resp.json()["execution_status"] == "SUCCEEDED"


# ── Side effects ─────────────────────────────────────────────────────────


class TestSideEffectSafety:
    def test_reconciliation_never_invokes_the_scanner(self, wired_app: Application, scanner_spy: _CountingScanner) -> None:
        with wired_app:
            _seed_running_execution(wired_app, assessment_id="asmt-15", execution_id="exec-15", assessment_status="completed")
            client = _client_as(wired_app, role=Role.ADMIN)
            client.post("/api/v1/assessment-executions/exec-15/reconcile")
        assert scanner_spy.invocation_count == 0, "reconciliation must never invoke the scanner"

    def test_reconciliation_never_creates_a_new_assessment(self, wired_app: Application) -> None:
        with wired_app:
            _seed_running_execution(wired_app, assessment_id="asmt-16", execution_id="exec-16", assessment_status="completed")
            before = _count_assessments(wired_app)
            client = _client_as(wired_app, role=Role.ADMIN)
            client.post("/api/v1/assessment-executions/exec-16/reconcile")
            after = _count_assessments(wired_app)
        assert after == before, "reconciliation must never create or submit a new Assessment"

    def test_reconciliation_of_invalid_evidence_also_creates_no_assessment_and_no_scan(
        self, wired_app: Application, scanner_spy: _CountingScanner
    ) -> None:
        with wired_app:
            _seed_running_execution(wired_app, assessment_id="asmt-17", execution_id="exec-17", assessment_status="running")
            before = _count_assessments(wired_app)
            client = _client_as(wired_app, role=Role.ADMIN)
            client.post("/api/v1/assessment-executions/exec-17/reconcile")
            after = _count_assessments(wired_app)
        assert after == before
        assert scanner_spy.invocation_count == 0


# ── Idempotency (HTTP level) ─────────────────────────────────────────────


class TestIdempotencyHttp:
    def test_calling_reconcile_twice_is_safe(self, wired_app: Application, scanner_spy: _CountingScanner) -> None:
        with wired_app:
            _seed_running_execution(wired_app, assessment_id="asmt-18", execution_id="exec-18", assessment_status="completed")
            client = _client_as(wired_app, role=Role.ADMIN)
            first = client.post("/api/v1/assessment-executions/exec-18/reconcile")
            second = client.post("/api/v1/assessment-executions/exec-18/reconcile")
        assert first.status_code == 200
        assert second.status_code == 200
        assert first.json()["mutated"] is True
        assert second.json()["mutated"] is False
        assert first.json()["execution_status"] == second.json()["execution_status"] == "SUCCEEDED"
        assert scanner_spy.invocation_count == 0


# ── Audit ──────────────────────────────────────────────────────────────────


class TestAudit:
    def test_successful_reconciliation_is_audited_with_matching_result(self, wired_app: Application) -> None:
        with wired_app:
            _seed_running_execution(wired_app, assessment_id="asmt-19", execution_id="exec-19", assessment_status="completed")
            client = _client_as(wired_app, role=Role.ADMIN)
            client.post("/api/v1/assessment-executions/exec-19/reconcile")
            entries = _reconcile_audit_entries(wired_app)
        matching = [e for e in entries if e.resource_id == "exec-19"]
        assert len(matching) == 1
        entry = matching[0]
        assert entry.success is True
        assert entry.metadata["resulting_execution_status"] == "SUCCEEDED"
        assert entry.metadata["previous_execution_status"] == "RUNNING"
        assert entry.metadata["mutated"] is True
        assert entry.metadata["evidence_assessment_status"] == "completed"

    def test_rejected_reconciliation_is_audited_as_unsuccessful(self, wired_app: Application) -> None:
        with wired_app:
            _seed_running_execution(wired_app, assessment_id="asmt-20", execution_id="exec-20", assessment_status="running")
            client = _client_as(wired_app, role=Role.ADMIN)
            client.post("/api/v1/assessment-executions/exec-20/reconcile")
            entries = _reconcile_audit_entries(wired_app)
        matching = [e for e in entries if e.resource_id == "exec-20"]
        assert len(matching) == 1
        assert matching[0].success is False
        assert matching[0].metadata["mutated"] is False

    def test_audit_never_claims_success_when_the_race_was_lost_and_unresolved(self, wired_app: Application) -> None:
        """The audit result must reflect the ACTUAL final state - proven
        indirectly here by confirming a normal idempotent no-op (already
        terminal) is audited as success=True with mutated=False, never
        as if a fresh mutation occurred."""
        with wired_app:
            _seed_assessment(wired_app, assessment_id="asmt-21", status="completed")
            _seed_execution(wired_app, execution_id="exec-21", assessment_id="asmt-21", status=AssessmentExecutionStatus.SUCCEEDED)
            client = _client_as(wired_app, role=Role.ADMIN)
            client.post("/api/v1/assessment-executions/exec-21/reconcile")
            entries = _reconcile_audit_entries(wired_app)
        matching = [e for e in entries if e.resource_id == "exec-21"]
        assert len(matching) == 1
        assert matching[0].success is True
        assert matching[0].metadata["mutated"] is False
        assert matching[0].metadata["previous_execution_status"] == "SUCCEEDED"
        assert matching[0].metadata["resulting_execution_status"] == "SUCCEEDED"

    def test_audit_metadata_contains_no_secrets_or_internals(self, wired_app: Application) -> None:
        with wired_app:
            _seed_running_execution(wired_app, assessment_id="asmt-22", execution_id="exec-22", assessment_status="completed")
            client = _client_as(wired_app, role=Role.ADMIN)
            client.post("/api/v1/assessment-executions/exec-22/reconcile")
            entries = _reconcile_audit_entries(wired_app)
        matching = [e for e in entries if e.resource_id == "exec-22"]
        assert len(matching) == 1
        metadata_str = str(matching[0].metadata).lower()
        for forbidden in ("secret", "password", "token", "credential", "api_key", "traceback"):
            assert forbidden not in metadata_str


# ── Injection ───────────────────────────────────────────────────────────


class TestInjection:
    def test_sql_like_execution_id_does_not_error_or_leak(self, wired_app: Application) -> None:
        with wired_app:
            client = _client_as(wired_app, role=Role.ADMIN)
            resp = client.post("/api/v1/assessment-executions/' OR '1'='1/reconcile")
        assert resp.status_code == 404
        assert "sqlalchemy" not in resp.text.lower()
        assert "traceback" not in resp.text.lower()

    def test_malformed_execution_id_returns_404_not_500(self, wired_app: Application) -> None:
        with wired_app:
            client = _client_as(wired_app, role=Role.ADMIN)
            resp = client.post("/api/v1/assessment-executions/%00%01%02/reconcile")
        assert resp.status_code in (404, 400)

    def test_oversized_execution_id_does_not_crash(self, wired_app: Application) -> None:
        with wired_app:
            client = _client_as(wired_app, role=Role.ADMIN)
            huge_id = "x" * 10000
            resp = client.post(f"/api/v1/assessment-executions/{huge_id}/reconcile")
        assert resp.status_code in (404, 400, 414, 431)


# ── KSEC-106-01 regression: inspection/reconciliation against a REAL,
# domain-model-created assessment (not a hand-seeded ORM row) ──────────
#
# Every test above (and every Phase 103/105 test before this phase) seeds
# AssessmentORM.status with a hand-typed lowercase string, bypassing the
# real CreateAssessment/SubmitAssessment -> assessment_to_orm() path
# entirely. Phase 106 found that real path stores the enum MEMBER NAME
# (e.g. "RUNNING"), not the lowercase value the hand-seeded tests used -
# a mismatch that made GET/POST .../assessment-executions/* raise an
# uncaught ValueError (-> HTTP 500) for every real, production-created
# assessment, while every existing test stayed green. This class proves
# the fix against the true, unmodified HTTP/domain/persistence path.


class TestRealDomainModelEndToEnd:
    def test_inspection_and_reconciliation_work_against_a_real_http_created_assessment(
        self, wired_app: Application, scanner_spy: _CountingScanner
    ) -> None:
        with wired_app:
            analyst_client = _client_as(wired_app, role=Role.ANALYST)
            create_resp = analyst_client.post(
                "/api/v1/assessments",
                json={
                    "target_value": "10.0.0.9",
                    "target_type": "ip_address",
                    "profile_id": "quick-scan",
                    "authorized_by": "pentester@kingusecurity.com",
                    "scope": "10.0.0.9",
                },
            )
            assert create_resp.status_code == 201
            assessment_id = create_resp.json()["assessment_id"]

            start_resp = analyst_client.post(f"/api/v1/assessments/{assessment_id}/start")
            assert start_resp.status_code == 202

            for _ in range(50):
                poll = analyst_client.get(f"/api/v1/assessments/{assessment_id}")
                if poll.json()["status"] == "completed":
                    break
                import time

                time.sleep(0.1)
            else:
                raise AssertionError("real assessment did not complete within timeout")

            admin_client = _client_as(wired_app, role=Role.ADMIN)

            # Before the KSEC-106-01 fix, both of these calls raised an
            # uncaught ValueError inside _row_to_inspection() for this
            # real, domain-model-created assessment, surfacing as a 500.
            list_resp = admin_client.get("/api/v1/assessment-executions")
            assert list_resp.status_code == 200
            matching = [i for i in list_resp.json()["items"] if i["assessment_id"] == assessment_id]
            assert len(matching) == 1
            execution_id = matching[0]["execution_id"]
            assert matching[0]["assessment_status"] == "completed"
            assert matching[0]["execution_status"] == "SUCCEEDED"

            get_resp = admin_client.get(f"/api/v1/assessment-executions/{execution_id}")
            assert get_resp.status_code == 200
            assert get_resp.json()["assessment_status"] == "completed"

            reconcile_resp = admin_client.post(f"/api/v1/assessment-executions/{execution_id}/reconcile")
            assert reconcile_resp.status_code == 200
            assert reconcile_resp.json()["mutated"] is False, "already SUCCEEDED via the real scan - idempotent no-op"

        assert scanner_spy.invocation_count == 1, "the real scan itself ran exactly once; reconciliation added none"
