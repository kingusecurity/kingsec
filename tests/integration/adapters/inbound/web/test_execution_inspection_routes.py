"""KSEC-103-01: HTTP-level security and behavior tests for the
admin-only assessment-execution inspection endpoints.

Real wired FastAPI application, real on-disk SQLite (via ``create_schema``
on a temp-dir-backed engine, the same fixture pattern already established
in test_web_integration.py), real ``require_admin``/``require_role`` logic
- only ``get_current_user`` is overridden (never ``require_admin`` itself)
so the actual role-gate under test still runs for real.
"""

from __future__ import annotations

import io
from datetime import UTC, datetime

import pytest
from cryptography.fernet import Fernet
from fastapi.testclient import TestClient

from kingsec.adapters.inbound.web.app import create_fastapi_app
from kingsec.adapters.inbound.web.auth import CurrentUser, get_current_user
from kingsec.application.assessment_execution_ledger import AssessmentExecutionStatus
from kingsec.application.ports import ScannerPort, TokenClaims
from kingsec.bootstrap.application import Application
from kingsec.bootstrap.composition import create_wired_application
from kingsec.domain import Finding, Role, Severity, Target
from kingsec.infrastructure.persistence import create_database_engine, create_schema
from kingsec.infrastructure.persistence.models import (
    AssessmentExecutionORM,
    AssessmentORM,
    ScheduleOccurrenceORM,
    ScheduleORM,
)

_TEST_FERNET_KEY = Fernet.generate_key().decode()
_TEST_JWT_SECRET = "test-jwt-secret-" + Fernet.generate_key().decode()
_TEST_PEPPER = "test-pepper-" + Fernet.generate_key().decode()


class _StubScanner(ScannerPort):
    def scan(self, target: Target):
        return [Finding.create("SQLi", "injectable param", Severity.CRITICAL)]

    def compatible_scanners(self, target: Target) -> dict[str, str]:
        return {"stub": "Stub Scanner"}


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
def wired_app(tmp_path, monkeypatch) -> Application:
    monkeypatch.setenv("KINGSEC_STORAGE__DATA_DIR", str(tmp_path))
    monkeypatch.setenv("KINGSEC_SECRETS__ENCRYPTION_KEY", _TEST_FERNET_KEY)
    monkeypatch.setenv("KINGSEC_JWT__SECRET_KEY", _TEST_JWT_SECRET)
    monkeypatch.setenv("KINGSEC_SECRETS__API_KEY_PEPPER", _TEST_PEPPER)
    app = create_wired_application(log_stream=io.StringIO(), ensure_directories=False, validate_migrations=False)
    engine = create_database_engine(settings=app.settings)
    create_schema(engine)
    engine.dispose()
    app.container.register_instance(ScannerPort, _StubScanner())
    return app


def _client_as(app: Application, role: Role | None) -> TestClient:
    """A fresh TestClient with ``get_current_user`` overridden to the given
    role (or left un-overridden, with no Authorization header, for
    ``role=None`` - a genuinely unauthenticated request). Deliberately
    never overrides ``require_admin``/``require_role`` itself - the real
    role-gate under test must actually run."""
    fastapi_app = create_fastapi_app(app)
    if role is not None:
        fastapi_app.dependency_overrides[get_current_user] = lambda: _make_user(role)
    return TestClient(fastapi_app, raise_server_exceptions=False)


def _now() -> str:
    return datetime.now(UTC).isoformat()


def _seed_assessment(app: Application, *, assessment_id: str, status: str, schedule_occurrence_id: str | None = None) -> None:
    engine = create_database_engine(settings=app.settings)
    from sqlalchemy.orm import sessionmaker

    session_factory = sessionmaker(bind=engine, expire_on_commit=False, future=True)
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
                schedule_occurrence_id=schedule_occurrence_id,
                scanner_summary=[],
            )
        )
        session.commit()
    engine.dispose()


def _seed_execution(app: Application, *, execution_id: str, assessment_id: str, status: AssessmentExecutionStatus) -> None:
    engine = create_database_engine(settings=app.settings)
    from sqlalchemy.orm import sessionmaker

    session_factory = sessionmaker(bind=engine, expire_on_commit=False, future=True)
    with session_factory() as session:
        session.add(
            AssessmentExecutionORM(
                id=execution_id,
                assessment_id=assessment_id,
                status=status.value,
                version=1,
                created_at=_now(),
                updated_at=_now(),
            )
        )
        session.commit()
    engine.dispose()


def _seed_schedule_and_occurrence(
    app: Application, *, schedule_id: str, occurrence_id: str, owner_user_id: str, occurrence_key: str
) -> None:
    engine = create_database_engine(settings=app.settings)
    from sqlalchemy.orm import sessionmaker

    session_factory = sessionmaker(bind=engine, expire_on_commit=False, future=True)
    with session_factory() as session:
        session.add(
            ScheduleORM(
                id=schedule_id,
                name="Nightly scan",
                owner_user_id=owner_user_id,
                target="10.0.0.5",
                schedule_type="cron",
                cron_expression="0 2 * * *",
                created_at=_now(),
                updated_at=_now(),
            )
        )
        session.add(
            ScheduleOccurrenceORM(
                id=occurrence_id,
                schedule_id=schedule_id,
                occurrence_key=occurrence_key,
                status="SUBMITTED",
                assessment_id=None,
                version=1,
                claimed_at=_now(),
                updated_at=_now(),
            )
        )
        session.commit()
    engine.dispose()


# ── A. Authorization ─────────────────────────────────────────────────────


class TestAuthorizationMatrix:
    def test_unauthenticated_is_rejected(self, wired_app: Application) -> None:
        with wired_app:
            client = _client_as(wired_app, role=None)
            resp = client.get("/api/v1/assessment-executions")
        assert resp.status_code == 401

    def test_viewer_is_rejected(self, wired_app: Application) -> None:
        with wired_app:
            client = _client_as(wired_app, role=Role.VIEWER)
            resp = client.get("/api/v1/assessment-executions")
        assert resp.status_code == 403

    def test_analyst_is_rejected(self, wired_app: Application) -> None:
        with wired_app:
            client = _client_as(wired_app, role=Role.ANALYST)
            resp = client.get("/api/v1/assessment-executions")
        assert resp.status_code == 403

    def test_admin_is_permitted(self, wired_app: Application) -> None:
        with wired_app:
            client = _client_as(wired_app, role=Role.ADMIN)
            resp = client.get("/api/v1/assessment-executions")
        assert resp.status_code == 200

    def test_single_execution_lookup_also_enforces_admin(self, wired_app: Application) -> None:
        with wired_app:
            viewer_client = _client_as(wired_app, role=Role.VIEWER)
            resp = viewer_client.get("/api/v1/assessment-executions/exec-anything")
        assert resp.status_code == 403


# ── B. Empty result ───────────────────────────────────────────────────────


class TestEmptyResult:
    def test_empty_database_returns_empty_list_not_an_error(self, wired_app: Application) -> None:
        with wired_app:
            client = _client_as(wired_app, role=Role.ADMIN)
            resp = client.get("/api/v1/assessment-executions")
        assert resp.status_code == 200
        body = resp.json()
        assert body["items"] == []
        assert body["total"] == 0


# ── C/D/E. Unresolved states ──────────────────────────────────────────────


class TestUnresolvedStates:
    @pytest.mark.parametrize(
        "exec_status", [AssessmentExecutionStatus.REQUESTED, AssessmentExecutionStatus.CLAIMED]
    )
    def test_requested_and_claimed_are_visible_and_unresolved(
        self, wired_app: Application, exec_status: AssessmentExecutionStatus
    ) -> None:
        with wired_app:
            _seed_assessment(wired_app, assessment_id="asmt-1", status="running")
            _seed_execution(wired_app, execution_id="exec-1", assessment_id="asmt-1", status=exec_status)

            client = _client_as(wired_app, role=Role.ADMIN)
            resp = client.get("/api/v1/assessment-executions/exec-1")
        assert resp.status_code == 200
        body = resp.json()
        assert body["execution_status"] == exec_status.value
        assert body["classification"] == "UNRESOLVED"

    def test_running_with_running_assessment_is_visible_and_unresolved(self, wired_app: Application) -> None:
        with wired_app:
            _seed_assessment(wired_app, assessment_id="asmt-2", status="running")
            _seed_execution(
                wired_app, execution_id="exec-2", assessment_id="asmt-2", status=AssessmentExecutionStatus.RUNNING
            )
            client = _client_as(wired_app, role=Role.ADMIN)
            resp = client.get("/api/v1/assessment-executions/exec-2")
        assert resp.status_code == 200
        body = resp.json()
        assert body["classification"] == "UNRESOLVED"

    def test_unresolved_only_filter_excludes_terminal_executions(self, wired_app: Application) -> None:
        with wired_app:
            _seed_assessment(wired_app, assessment_id="asmt-3a", status="running")
            _seed_execution(
                wired_app,
                execution_id="exec-3a",
                assessment_id="asmt-3a",
                status=AssessmentExecutionStatus.REQUESTED,
            )
            _seed_assessment(wired_app, assessment_id="asmt-3b", status="completed")
            _seed_execution(
                wired_app,
                execution_id="exec-3b",
                assessment_id="asmt-3b",
                status=AssessmentExecutionStatus.SUCCEEDED,
            )
            client = _client_as(wired_app, role=Role.ADMIN)
            resp = client.get("/api/v1/assessment-executions", params={"unresolved_only": True})
        assert resp.status_code == 200
        body = resp.json()
        ids = {item["execution_id"] for item in body["items"]}
        assert ids == {"exec-3a"}


# ── F/G. Reconcilable ──────────────────────────────────────────────────────


class TestReconcilable:
    def test_running_plus_completed_assessment_is_reconcilable(self, wired_app: Application) -> None:
        with wired_app:
            _seed_assessment(wired_app, assessment_id="asmt-4", status="completed")
            _seed_execution(
                wired_app, execution_id="exec-4", assessment_id="asmt-4", status=AssessmentExecutionStatus.RUNNING
            )
            client = _client_as(wired_app, role=Role.ADMIN)
            resp = client.get("/api/v1/assessment-executions/exec-4")
        assert resp.status_code == 200
        body = resp.json()
        assert body["classification"] == "RECONCILABLE"
        assert body["execution_status"] == "RUNNING", "inspection must not have mutated the execution"

    def test_running_plus_failed_assessment_is_reconcilable(self, wired_app: Application) -> None:
        with wired_app:
            _seed_assessment(wired_app, assessment_id="asmt-5", status="failed")
            _seed_execution(
                wired_app, execution_id="exec-5", assessment_id="asmt-5", status=AssessmentExecutionStatus.RUNNING
            )
            client = _client_as(wired_app, role=Role.ADMIN)
            resp = client.get("/api/v1/assessment-executions/exec-5")
        assert resp.status_code == 200
        assert resp.json()["classification"] == "RECONCILABLE"


# ── H. Terminal ────────────────────────────────────────────────────────────


class TestTerminal:
    @pytest.mark.parametrize(
        ("exec_status", "assessment_status"),
        [(AssessmentExecutionStatus.SUCCEEDED, "completed"), (AssessmentExecutionStatus.FAILED, "failed")],
    )
    def test_terminal_executions_are_visible_and_classified_terminal(
        self, wired_app: Application, exec_status: AssessmentExecutionStatus, assessment_status: str
    ) -> None:
        with wired_app:
            _seed_assessment(wired_app, assessment_id="asmt-6", status=assessment_status)
            _seed_execution(wired_app, execution_id="exec-6", assessment_id="asmt-6", status=exec_status)
            client = _client_as(wired_app, role=Role.ADMIN)
            resp = client.get("/api/v1/assessment-executions/exec-6")
        assert resp.status_code == 200
        body = resp.json()
        assert body["classification"] == "TERMINAL"
        assert body["execution_status"] == exec_status.value


# ── I. Inconsistent ─────────────────────────────────────────────────────────


class TestInconsistentData:
    def test_succeeded_with_running_assessment_is_reported_inconsistent_not_reinterpreted(
        self, wired_app: Application
    ) -> None:
        with wired_app:
            _seed_assessment(wired_app, assessment_id="asmt-7", status="running")
            _seed_execution(
                wired_app, execution_id="exec-7", assessment_id="asmt-7", status=AssessmentExecutionStatus.SUCCEEDED
            )
            client = _client_as(wired_app, role=Role.ADMIN)
            resp = client.get("/api/v1/assessment-executions/exec-7")
        assert resp.status_code == 200
        body = resp.json()
        assert body["classification"] == "INCONSISTENT"
        assert body["execution_status"] == "SUCCEEDED", "must not silently reinterpret the durable execution status"
        assert body["assessment_status"] == "running", "must not silently reinterpret the durable assessment status"

    def test_failed_with_completed_assessment_is_reported_inconsistent(self, wired_app: Application) -> None:
        with wired_app:
            _seed_assessment(wired_app, assessment_id="asmt-8", status="completed")
            _seed_execution(
                wired_app, execution_id="exec-8", assessment_id="asmt-8", status=AssessmentExecutionStatus.FAILED
            )
            client = _client_as(wired_app, role=Role.ADMIN)
            resp = client.get("/api/v1/assessment-executions/exec-8")
        assert resp.status_code == 200
        assert resp.json()["classification"] == "INCONSISTENT"


# ── J/K. Manual vs scheduled ────────────────────────────────────────────────


class TestManualAndScheduledAssessments:
    def test_manual_assessment_execution_has_null_schedule_fields(self, wired_app: Application) -> None:
        with wired_app:
            _seed_assessment(wired_app, assessment_id="asmt-9", status="running")
            _seed_execution(
                wired_app, execution_id="exec-9", assessment_id="asmt-9", status=AssessmentExecutionStatus.RUNNING
            )
            client = _client_as(wired_app, role=Role.ADMIN)
            resp = client.get("/api/v1/assessment-executions/exec-9")
        assert resp.status_code == 200
        body = resp.json()
        assert body["schedule_id"] is None
        assert body["occurrence_key"] is None
        assert body["schedule_owner_user_id"] is None

    def test_scheduled_assessment_execution_reports_full_chain(self, wired_app: Application) -> None:
        with wired_app:
            _seed_schedule_and_occurrence(
                wired_app,
                schedule_id="sched-10",
                occurrence_id="occ-10",
                owner_user_id="carol",
                occurrence_key="2026-09-06T04:00:00",
            )
            _seed_assessment(
                wired_app, assessment_id="asmt-10", status="running", schedule_occurrence_id="occ-10"
            )
            _seed_execution(
                wired_app, execution_id="exec-10", assessment_id="asmt-10", status=AssessmentExecutionStatus.RUNNING
            )
            client = _client_as(wired_app, role=Role.ADMIN)
            resp = client.get("/api/v1/assessment-executions/exec-10")
        assert resp.status_code == 200
        body = resp.json()
        assert body["schedule_id"] == "sched-10"
        assert body["schedule_occurrence_id"] == "occ-10"
        assert body["occurrence_key"] == "2026-09-06T04:00:00"
        assert body["schedule_owner_user_id"] == "carol"


# ── L. IDOR / non-disclosure ─────────────────────────────────────────────


class TestObjectLevelAccess:
    def test_nonexistent_execution_id_returns_clean_404_not_a_leak(self, wired_app: Application) -> None:
        with wired_app:
            client = _client_as(wired_app, role=Role.ADMIN)
            resp = client.get("/api/v1/assessment-executions/does-not-exist")
        assert resp.status_code == 404
        assert "does-not-exist" not in resp.text or "traceback" not in resp.text.lower()

    def test_non_admin_cannot_learn_whether_an_execution_exists(self, wired_app: Application) -> None:
        """A viewer/analyst must be rejected identically (403) whether or
        not the execution actually exists - the platform is intentionally
        global-admin (proven from source: Role is a flat VIEWER < ANALYST
        < ADMIN hierarchy with no per-tenant admin scoping), so the only
        access boundary here IS the admin gate itself."""
        with wired_app:
            _seed_assessment(wired_app, assessment_id="asmt-11", status="running")
            _seed_execution(
                wired_app, execution_id="exec-11", assessment_id="asmt-11", status=AssessmentExecutionStatus.RUNNING
            )
            client = _client_as(wired_app, role=Role.VIEWER)
            resp_real = client.get("/api/v1/assessment-executions/exec-11")
            resp_fake = client.get("/api/v1/assessment-executions/does-not-exist")
        assert resp_real.status_code == resp_fake.status_code == 403


# ── M. Injection / validation ────────────────────────────────────────────


class TestInjectionAndValidation:
    def test_sql_like_execution_id_does_not_error_or_leak(self, wired_app: Application) -> None:
        with wired_app:
            client = _client_as(wired_app, role=Role.ADMIN)
            resp = client.get("/api/v1/assessment-executions/' OR '1'='1")
        assert resp.status_code == 404
        assert "sqlalchemy" not in resp.text.lower()
        assert "traceback" not in resp.text.lower()

    def test_invalid_status_value_returns_422_not_500(self, wired_app: Application) -> None:
        with wired_app:
            client = _client_as(wired_app, role=Role.ADMIN)
            resp = client.get("/api/v1/assessment-executions", params={"status": "NOT_A_REAL_STATUS"})
        assert resp.status_code == 422

    def test_oversized_page_size_returns_422_not_a_database_dump(self, wired_app: Application) -> None:
        with wired_app:
            client = _client_as(wired_app, role=Role.ADMIN)
            resp = client.get("/api/v1/assessment-executions", params={"limit": 100000})
        assert resp.status_code == 422

    def test_negative_offset_returns_422(self, wired_app: Application) -> None:
        with wired_app:
            client = _client_as(wired_app, role=Role.ADMIN)
            resp = client.get("/api/v1/assessment-executions", params={"offset": -1})
        assert resp.status_code == 422

    def test_wildcard_like_execution_id_is_treated_as_a_literal_value(self, wired_app: Application) -> None:
        with wired_app:
            client = _client_as(wired_app, role=Role.ADMIN)
            resp = client.get("/api/v1/assessment-executions/%25%25%25")
        assert resp.status_code == 404


# ── N. Pagination ──────────────────────────────────────────────────────────


class TestPagination:
    def test_default_and_explicit_pagination(self, wired_app: Application) -> None:
        with wired_app:
            for i in range(5):
                _seed_assessment(wired_app, assessment_id=f"asmt-p{i}", status="running")
                _seed_execution(
                    wired_app,
                    execution_id=f"exec-p{i}",
                    assessment_id=f"asmt-p{i}",
                    status=AssessmentExecutionStatus.REQUESTED,
                )
            client = _client_as(wired_app, role=Role.ADMIN)
            resp_default = client.get("/api/v1/assessment-executions")
            resp_page1 = client.get("/api/v1/assessment-executions", params={"limit": 2, "offset": 0})
            resp_page2 = client.get("/api/v1/assessment-executions", params={"limit": 2, "offset": 2})

        assert resp_default.status_code == resp_page1.status_code == resp_page2.status_code == 200
        assert resp_default.json()["total"] == 5
        assert len(resp_page1.json()["items"]) == 2
        assert len(resp_page2.json()["items"]) == 2
        ids_p1 = {i["execution_id"] for i in resp_page1.json()["items"]}
        ids_p2 = {i["execution_id"] for i in resp_page2.json()["items"]}
        assert ids_p1.isdisjoint(ids_p2)
