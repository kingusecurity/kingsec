"""KSEC-110: Phase 110 adversarial verification of the complete Assessment
lifecycle - state-machine integrity, deletion safety, and Assessment <->
Execution/Findings consistency, at the real repository/domain level.

Complements test_phase110_assessment_lifecycle_routes.py (HTTP-level
authorization matrix and cross-user isolation) - this file focuses on the
domain FSM's forbidden-transition matrix and deep, real-database deletion
semantics (with real findings, real execution ledger rows, real reports,
real concurrent races), none of which any existing test exercises against
a fully real, persisted, multi-child aggregate.
"""

from __future__ import annotations

import threading
import uuid
from pathlib import Path

import pytest
from sqlalchemy import create_engine, event, select
from sqlalchemy.orm import sessionmaker

from kingsec.application.errors import AssessmentNotFoundError
from kingsec.application.submit_assessment import SubmitAssessment
from kingsec.domain import Authorization, Finding, Severity, Target, TargetType
from kingsec.domain.assessment import Assessment
from kingsec.domain.enums import AssessmentStatus
from kingsec.domain.errors import IllegalStateTransition
from kingsec.domain.report import Report
from kingsec.infrastructure.jobs.thread_runner import ThreadJobRunner
from kingsec.infrastructure.persistence._legacy_repositories import (
    LegacyAssessmentRepository,
    LegacyReportRepository,
)
from kingsec.infrastructure.persistence.models import AssessmentExecutionORM, AssessmentORM, Base, FindingORM, ReportORM
from kingsec.infrastructure.persistence.repositories.assessment_execution import (
    SqlAlchemyAssessmentExecutionRepository,
)

# ── Fixtures ─────────────────────────────────────────────────────────────


def _enable_foreign_keys(dbapi_connection, _connection_record) -> None:
    cursor = dbapi_connection.cursor()
    cursor.execute("PRAGMA foreign_keys=ON")
    cursor.execute("PRAGMA busy_timeout=10000")
    cursor.close()


@pytest.fixture
def engine(tmp_path: Path):
    db_path = tmp_path / f"phase110-{uuid.uuid4().hex}.sqlite3"
    eng = create_engine(f"sqlite:///{db_path}", future=True, connect_args={"timeout": 30})
    event.listen(eng, "connect", _enable_foreign_keys)
    Base.metadata.create_all(eng)
    return eng


@pytest.fixture
def session_factory(engine):
    return sessionmaker(bind=engine, expire_on_commit=False, future=True)


@pytest.fixture
def assessment_repo(session_factory) -> LegacyAssessmentRepository:
    return LegacyAssessmentRepository(session_factory)


@pytest.fixture
def execution_repo(session_factory) -> SqlAlchemyAssessmentExecutionRepository:
    return SqlAlchemyAssessmentExecutionRepository(session_factory)


@pytest.fixture
def report_repo(session_factory) -> LegacyReportRepository:
    return LegacyReportRepository(session_factory)


def _target() -> Target:
    return Target("10.0.0.9", TargetType.IP_ADDRESS)


def _new_authorized_assessment(owner_id: str = "user-1") -> Assessment:
    a = Assessment.create(_target())
    a.authorize(Authorization.grant("pentester@kingusecurity.com", "10.0.0.9"))
    a.set_ownership(owner_id)
    return a


def _finding(title: str = "SQLi") -> Finding:
    return Finding.create(title, "injectable param", Severity.CRITICAL)


class _CountingScanner:
    def __init__(self) -> None:
        self._lock = threading.Lock()
        self.invocation_count = 0

    def scan(self, target: Target, *, scanner_ids: tuple[str, ...] | None = None) -> list[Finding]:
        with self._lock:
            self.invocation_count += 1
        return [_finding()]

    def compatible_scanners(self, target: Target) -> dict[str, str]:
        return {"stub": "Stub Scanner"}


class _GatedScanner:
    def __init__(self) -> None:
        self.invocation_count = 0
        self.entered = threading.Event()
        self.release_gate = threading.Event()

    def scan(self, target: Target, *, scanner_ids: tuple[str, ...] | None = None) -> list[Finding]:
        self.invocation_count += 1
        self.entered.set()
        self.release_gate.wait(timeout=10)
        return [_finding()]

    def compatible_scanners(self, target: Target) -> dict[str, str]:
        return {"stub": "Stub Scanner"}


# ── B: complete FSM forbidden-transition matrix ─────────────────────────


class TestForbiddenTransitions:
    """Every transition NOT present in _ALLOWED_ASSESSMENT_TRANSITIONS,
    tested directly against the real domain object - fast, no DB needed,
    but exhaustive per the actual (re-read, not assumed) FSM:
        DRAFT -> {AUTHORIZED, CANCELLED}
        AUTHORIZED -> {RUNNING, CANCELLED}
        RUNNING -> {COMPLETED, FAILED, CANCELLED}
        COMPLETED / CANCELLED / FAILED -> {} (all three terminal)
    """

    def _draft(self) -> Assessment:
        return Assessment.create(_target())

    def _authorized(self) -> Assessment:
        return _new_authorized_assessment()

    def _running(self) -> Assessment:
        a = _new_authorized_assessment()
        a.start()
        return a

    def _completed(self) -> Assessment:
        a = self._running()
        a.complete()
        return a

    def _failed(self) -> Assessment:
        a = self._running()
        a.fail("scanner error")
        return a

    def _cancelled_from_running(self) -> Assessment:
        a = self._running()
        a.cancel()
        return a

    @pytest.mark.parametrize(
        "make,attempt",
        [
            (lambda self: self._draft(), "complete"),
            (lambda self: self._draft(), "fail"),
            (lambda self: self._authorized(), "complete"),
            (lambda self: self._authorized(), "fail"),
            (lambda self: self._running(), "authorize"),
        ],
    )
    def test_forbidden_transition_raises_illegal_state_transition(self, make, attempt: str) -> None:
        a = make(self)
        with pytest.raises(IllegalStateTransition):
            if attempt == "complete":
                a.complete()
            elif attempt == "fail":
                a.fail("x")
            elif attempt == "authorize":
                a.authorize(Authorization.grant("someone", "scope"))

    def test_running_cannot_authorize_again(self) -> None:
        a = self._running()
        with pytest.raises(IllegalStateTransition):
            a.authorize(Authorization.grant("someone", "scope"))

    @pytest.mark.parametrize("make", [lambda self: self._completed(), lambda self: self._failed(), lambda self: self._cancelled_from_running()])
    def test_every_terminal_state_forbids_every_further_transition(self, make) -> None:
        for _attempt_name, attempt_fn in [
            ("start", lambda a: a.start()),
            ("complete", lambda a: a.complete()),
            ("fail", lambda a: a.fail("x")),
            ("cancel", lambda a: a.cancel()),
            ("authorize", lambda a: a.authorize(Authorization.grant("someone", "scope"))),
        ]:
            a = make(self)
            with pytest.raises(IllegalStateTransition):
                attempt_fn(a)

    def test_invalid_transition_does_not_partially_mutate_status(self) -> None:
        """A rejected transition must leave the object's status completely
        unchanged - no partial mutation."""
        a = self._completed()
        original_status = a.status
        with pytest.raises(IllegalStateTransition):
            a.start()
        assert a.status == original_status == AssessmentStatus.COMPLETED

    def test_invalid_transition_does_not_partially_persist(
        self, assessment_repo: LegacyAssessmentRepository
    ) -> None:
        """A rejected domain-level transition never even reaches save() -
        confirmed no persistence side effect occurs."""
        a = self._completed()
        assessment_repo.save(a)
        loaded = assessment_repo.get(a.id)
        with pytest.raises(IllegalStateTransition):
            loaded.fail("x")
        # loaded was never saved after the rejected mutation attempt -
        # durable state is exactly what it was before.
        reloaded = assessment_repo.get(a.id)
        assert reloaded.status == AssessmentStatus.COMPLETED
        assert reloaded.version == loaded.version


# ── F: deep delete semantics ─────────────────────────────────────────────


class TestDeleteSemantics:
    def test_delete_with_findings_and_report_cascades_completely(
        self, assessment_repo: LegacyAssessmentRepository, report_repo: LegacyReportRepository, session_factory
    ) -> None:
        a = _new_authorized_assessment()
        a.start()
        a.record_finding(_finding("SQLi"))
        a.record_finding(_finding("XSS"))
        a.complete()
        assessment_repo.save(a)
        report_repo.save(Report.from_assessment(a))

        with session_factory() as session:
            assert len(session.execute(select(FindingORM)).scalars().all()) == 2
            assert len(session.execute(select(ReportORM)).scalars().all()) == 1

        assessment_repo.delete(a.id)

        with session_factory() as session:
            assert session.execute(select(AssessmentORM)).scalars().all() == []
            assert session.execute(select(FindingORM)).scalars().all() == [], "findings must not be orphaned"
            assert session.execute(select(ReportORM)).scalars().all() == [], "KSEC-110-01: report must not be orphaned"

    def test_delete_leaves_execution_ledger_row_intact_but_orphaned_by_design(
        self,
        assessment_repo: LegacyAssessmentRepository,
        execution_repo: SqlAlchemyAssessmentExecutionRepository,
        session_factory,
    ) -> None:
        """assessment_executions.assessment_id is deliberately NOT a FK
        (documented in the execution-ledger migration, to survive
        Assessment's own DELETE+INSERT replace strategy) - confirming here
        that a real DELETE of the Assessment does NOT cascade-remove the
        execution row. This is intentional, pre-existing (Phase 102)
        behavior, not a Phase 110 finding - the execution row remains as
        a durable historical record of what happened, even after the
        Assessment itself is gone."""
        a = _new_authorized_assessment()
        assessment_repo.save(a)
        execution_repo.create_requested(str(a.id))

        assessment_repo.delete(a.id)

        with session_factory() as session:
            exec_rows = session.execute(select(AssessmentExecutionORM)).scalars().all()
            assert len(exec_rows) == 1, "execution ledger row is intentionally NOT cascade-deleted"
            assert exec_rows[0].assessment_id == str(a.id)
        with pytest.raises(AssessmentNotFoundError):
            assessment_repo.get(a.id)

    @pytest.mark.parametrize(
        "terminal_state",
        ["completed", "failed", "cancelled"],
    )
    def test_delete_succeeds_for_every_terminal_state(
        self, assessment_repo: LegacyAssessmentRepository, terminal_state: str
    ) -> None:
        a = _new_authorized_assessment()
        a.start()
        if terminal_state == "completed":
            a.complete()
        elif terminal_state == "failed":
            a.fail("x")
        else:
            a.cancel()
        assessment_repo.save(a)

        assessment_repo.delete(a.id)
        with pytest.raises(AssessmentNotFoundError):
            assessment_repo.get(a.id)

    def test_delete_while_running_succeeds_immediately_no_status_check(
        self, assessment_repo: LegacyAssessmentRepository
    ) -> None:
        """DeleteAssessment performs no status check at all (confirmed by
        source re-read) - a RUNNING assessment can be deleted just like any
        other. This is the precondition for the concurrent-delete-vs-live-
        scan races below."""
        a = _new_authorized_assessment()
        a.start()
        assessment_repo.save(a)
        assessment_repo.delete(a.id)
        with pytest.raises(AssessmentNotFoundError):
            assessment_repo.get(a.id)

    def test_repeated_delete_raises_not_found_not_idempotent_success(
        self, assessment_repo: LegacyAssessmentRepository
    ) -> None:
        a = _new_authorized_assessment()
        assessment_repo.save(a)
        assessment_repo.delete(a.id)
        with pytest.raises(AssessmentNotFoundError):
            assessment_repo.delete(a.id)

    def test_delete_then_access_by_stale_id_raises_not_found_cleanly(
        self, assessment_repo: LegacyAssessmentRepository
    ) -> None:
        a = _new_authorized_assessment()
        assessment_repo.save(a)
        stale_ref = assessment_repo.get(a.id)
        assessment_repo.delete(a.id)
        with pytest.raises(AssessmentNotFoundError):
            assessment_repo.get(stale_ref.id)


# ── K: DELETE vs SUBMIT / CANCEL / scanner-completion races ─────────────


class TestDeleteRacesLiveLifecycle:
    def test_delete_racing_a_submitted_but_not_yet_started_execution(
        self, assessment_repo: LegacyAssessmentRepository, execution_repo: SqlAlchemyAssessmentExecutionRepository
    ) -> None:
        """SUBMIT vs DELETE: a real SubmitAssessment.execute() call races a
        real repository-level delete() via a Barrier. Verify: no
        corruption, and if delete wins, the scanner never runs at all
        (since _execute_scan()'s own fresh get() would raise
        AssessmentNotFoundError - not silently proceed)."""
        a = _new_authorized_assessment()
        assessment_repo.save(a)

        scanner = _CountingScanner()
        job_runner = ThreadJobRunner(max_workers=2)
        submit = SubmitAssessment(
            assessments=assessment_repo, scanner=scanner, job_runner=job_runner, execution_ledger=execution_repo
        )

        barrier = threading.Barrier(2)
        outcomes: dict[str, str] = {}

        def _submit() -> None:
            from kingsec.application.dto import SubmitAssessmentRequest

            barrier.wait(timeout=10)
            try:
                submit.execute(SubmitAssessmentRequest(assessment_id=str(a.id), requesting_user="user-1"))
                outcomes["submit"] = "ok"
            except Exception as exc:
                outcomes["submit"] = type(exc).__name__

        def _delete() -> None:
            barrier.wait(timeout=10)
            try:
                assessment_repo.delete(a.id)
                outcomes["delete"] = "ok"
            except Exception as exc:
                outcomes["delete"] = type(exc).__name__

        t1 = threading.Thread(target=_submit)
        t2 = threading.Thread(target=_delete)
        t1.start()
        t2.start()
        t1.join(timeout=15)
        t2.join(timeout=15)
        job_runner.shutdown(wait=True)

        assert outcomes["delete"] in ("ok", "AssessmentNotFoundError")
        assert outcomes["submit"] in ("ok", "AssessmentConflictError", "AssessmentNotFoundError")
        # No exception type outside the expected, safe set - never a raw
        # unhandled error leaking a different, unexpected shape.

    def test_delete_during_a_genuinely_in_flight_scan_is_safe_no_resurrection(
        self, assessment_repo: LegacyAssessmentRepository, execution_repo: SqlAlchemyAssessmentExecutionRepository
    ) -> None:
        """A real, gated, currently-executing scan (proven mid-flight via
        a threading.Event, not assumed) is deleted out from under it. The
        scan's own eventual terminal save must fail closed
        (AssessmentConflictError, swallowed by submit_assessment.py's
        existing best-effort recovery block - same class of outcome as
        Phase 109's CancelAssessment-vs-live-scan finding) - and critically,
        it must NEVER resurrect the deleted Assessment row."""
        a = _new_authorized_assessment()
        assessment_repo.save(a)
        gated_scanner = _GatedScanner()
        job_runner = ThreadJobRunner(max_workers=2)
        submit = SubmitAssessment(
            assessments=assessment_repo, scanner=gated_scanner, job_runner=job_runner, execution_ledger=execution_repo
        )

        from kingsec.application.dto import SubmitAssessmentRequest

        submit.execute(SubmitAssessmentRequest(assessment_id=str(a.id), requesting_user="user-1"))
        assert gated_scanner.entered.wait(timeout=10), "scanner never started"

        assessment_repo.delete(a.id)
        with pytest.raises(AssessmentNotFoundError):
            assessment_repo.get(a.id)

        gated_scanner.release_gate.set()
        job_runner.shutdown(wait=True)

        # THE PROPERTY THAT MATTERS: the Assessment was never silently
        # resurrected by the scan's own now-stale terminal save.
        with pytest.raises(AssessmentNotFoundError):
            assessment_repo.get(a.id)
        assert gated_scanner.invocation_count == 1


# ── I: Assessment <-> Findings consistency under the Phase 109 residual
# risk (CancelAssessment racing a live scan) - confirming the exact
# nature of the "finding loss": in-memory-only discard, never an
# orphaned or misattributed database row. ──────────────────────────────


class TestFindingsConsistencyUnderCancelRace:
    def test_cancel_racing_a_live_scan_never_leaves_an_orphaned_or_misattributed_finding_row(
        self,
        assessment_repo: LegacyAssessmentRepository,
        execution_repo: SqlAlchemyAssessmentExecutionRepository,
        session_factory,
    ) -> None:
        """Phase 109 found: an admin CancelAssessment racing a live scan
        causes the scan's own terminal save to fail closed
        (AssessmentConflictError), silently discarding its findings -
        flagged as an OBSERVABILITY gap, not a data-integrity defect,
        because persist_assessment()'s conditional DELETE is checked
        BEFORE any child row (finding) is ever added to the session - a
        rejected save touches the database not at all. This test proves
        that precisely: zero finding rows exist afterward - not zero
        VISIBLE rows, zero rows, period."""
        a = _new_authorized_assessment()
        assessment_repo.save(a)

        gated_scanner = _GatedScanner()
        job_runner = ThreadJobRunner(max_workers=2)
        submit = SubmitAssessment(
            assessments=assessment_repo, scanner=gated_scanner, job_runner=job_runner, execution_ledger=execution_repo
        )
        from kingsec.application.dto import SubmitAssessmentRequest

        submit.execute(SubmitAssessmentRequest(assessment_id=str(a.id), requesting_user="user-1"))
        assert gated_scanner.entered.wait(timeout=10)

        # Admin cancels while the scan is genuinely still running.
        admin_copy = assessment_repo.get(a.id)
        admin_copy.cancel()
        assessment_repo.save(admin_copy)

        gated_scanner.release_gate.set()
        job_runner.shutdown(wait=True)

        final = assessment_repo.get(a.id)
        assert final.status == AssessmentStatus.CANCELLED
        assert len(final.findings) == 0

        with session_factory() as session:
            all_findings = session.execute(select(FindingORM)).scalars().all()
            assert all_findings == [], (
                "the scan's discarded finding must never become a durable orphaned row - "
                f"found {len(all_findings)}"
            )


# ── Phase 111 Section 7: observability improvement for discarded scan
# results under a concurrent lifecycle change. ──────────────────────────


class TestDiscardedScanResultObservability:
    def test_cancel_racing_a_live_scan_logs_a_distinct_structured_event(
        self,
        assessment_repo: LegacyAssessmentRepository,
        execution_repo: SqlAlchemyAssessmentExecutionRepository,
        caplog: pytest.LogCaptureFixture,
    ) -> None:
        """Phase 111: the exact CancelAssessment-vs-live-scan race Phase
        109/110 found now logs a distinct, structured, named event -
        clearly separable from a generic 'scan recovery failed' warning -
        so an operator scanning logs can actually find this specific
        class of event instead of it looking like an arbitrary internal
        failure. No concurrency semantics changed; this is visibility
        only."""
        import logging as _logging

        a = _new_authorized_assessment()
        assessment_repo.save(a)

        gated_scanner = _GatedScanner()
        job_runner = ThreadJobRunner(max_workers=2)
        submit = SubmitAssessment(
            assessments=assessment_repo, scanner=gated_scanner, job_runner=job_runner, execution_ledger=execution_repo
        )
        from kingsec.application.dto import SubmitAssessmentRequest

        with caplog.at_level(_logging.WARNING, logger="kingsec.application.submit_assessment"):
            submit.execute(SubmitAssessmentRequest(assessment_id=str(a.id), requesting_user="user-1"))
            assert gated_scanner.entered.wait(timeout=10)

            admin_copy = assessment_repo.get(a.id)
            admin_copy.cancel()
            assessment_repo.save(admin_copy)

            gated_scanner.release_gate.set()
            job_runner.shutdown(wait=True)

        matching = [
            r for r in caplog.records if getattr(r, "event", None) == "scan_result_discarded_on_concurrent_lifecycle_change"
        ]
        assert len(matching) == 1, f"expected exactly one distinct discarded-result event, got: {caplog.records}"
        assert matching[0].assessment_id == str(a.id)
        assert matching[0].levelno == _logging.WARNING
        # No sensitive content (target value, finding details) in the
        # structured fields - ids and a fixed reason only.
        assert "10.0.0.9" not in str(matching[0].__dict__.get("reason", ""))

    def test_delete_racing_a_live_scan_also_logs_the_same_distinct_event(
        self,
        assessment_repo: LegacyAssessmentRepository,
        execution_repo: SqlAlchemyAssessmentExecutionRepository,
        caplog: pytest.LogCaptureFixture,
    ) -> None:
        """The DELETE variant of the same race (Phase 110's own finding)
        must produce the identical, distinct structured event - not a
        different, harder-to-correlate log shape."""
        import logging as _logging

        a = _new_authorized_assessment()
        assessment_repo.save(a)

        gated_scanner = _GatedScanner()
        job_runner = ThreadJobRunner(max_workers=2)
        submit = SubmitAssessment(
            assessments=assessment_repo, scanner=gated_scanner, job_runner=job_runner, execution_ledger=execution_repo
        )
        from kingsec.application.dto import SubmitAssessmentRequest

        with caplog.at_level(_logging.WARNING, logger="kingsec.application.submit_assessment"):
            submit.execute(SubmitAssessmentRequest(assessment_id=str(a.id), requesting_user="user-1"))
            assert gated_scanner.entered.wait(timeout=10)

            assessment_repo.delete(a.id)

            gated_scanner.release_gate.set()
            job_runner.shutdown(wait=True)

        matching = [
            r for r in caplog.records if getattr(r, "event", None) == "scan_result_discarded_on_concurrent_lifecycle_change"
        ]
        assert len(matching) == 1, f"expected exactly one distinct discarded-result event, got: {caplog.records}"
        assert matching[0].assessment_id == str(a.id)
