"""KSEC-106-01: Phase 106 adversarial verification of the Phase 102-105
execution/reconciliation security model.

This file does NOT trust prior phase reports. Every test here exercises
REAL production code (the real ``SqlAlchemyAssessmentExecutionRepository``,
the real ``LegacyAssessmentRepository``, the real ``_execute_scan()``
background-thread function, the real ``ReconcileAssessmentExecution`` use
case) against a real on-disk SQLite database, using real threads and
``threading.Event``/``threading.Barrier`` for synchronization - never
``time.sleep()`` to "probably" win a race.

Sections covered (numbered per the Phase 106 prompt):
    Section 6  - can the scanner run twice / can a losing worker reach it
    Section 10 - can a stale worker run after admin reconciliation /
                 can an admin reconcile while a worker is genuinely
                 mid-scan
    Section 20 - Races D, E, F, K, L (2-admin races, admin-vs-worker,
                 explicit stale-version attacks)
    Section 25 - persistence delete-then-insert concurrent with a read
    Section 26 - terminal evidence falsification harness
"""

from __future__ import annotations

import threading
import uuid
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

import pytest
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

from kingsec.application.assessment_execution_ledger import (
    AssessmentExecutionStatus,
    ExecutionClassification,
    classify_execution,
)
from kingsec.application.errors import AssessmentExecutionNotReconcilableError
from kingsec.application.submit_assessment import _execute_scan
from kingsec.application.use_cases.execution_inspection_dto import ReconcileAssessmentExecutionRequest
from kingsec.application.use_cases.reconcile_assessment_execution import ReconcileAssessmentExecution
from kingsec.domain import AssessmentId, Finding, Severity, Target, TargetType
from kingsec.domain.enums import AssessmentStatus
from kingsec.infrastructure.persistence._legacy_repositories import LegacyAssessmentRepository
from kingsec.infrastructure.persistence.models import AssessmentExecutionORM, AssessmentORM, Base
from kingsec.infrastructure.persistence.repositories.assessment_execution import (
    SqlAlchemyAssessmentExecutionRepository,
)

# ── Fixtures ─────────────────────────────────────────────────────────────


@pytest.fixture
def engine(tmp_path: Path):
    db_path = tmp_path / f"phase106-{uuid.uuid4().hex}.sqlite3"
    eng = create_engine(f"sqlite:///{db_path}", future=True, connect_args={"timeout": 30})
    Base.metadata.create_all(eng)
    return eng


@pytest.fixture
def session_factory(engine):
    return sessionmaker(bind=engine, expire_on_commit=False, future=True)


@pytest.fixture
def execution_repo(session_factory) -> SqlAlchemyAssessmentExecutionRepository:
    return SqlAlchemyAssessmentExecutionRepository(session_factory)


@pytest.fixture
def assessment_repo(session_factory) -> LegacyAssessmentRepository:
    return LegacyAssessmentRepository(session_factory)


def _now() -> str:
    return datetime.now(UTC).isoformat()


def _seed_assessment_row(session_factory, *, assessment_id: str, status: str) -> None:
    """Seed a raw assessments row directly (bypassing the domain model) -
    used for the terminal-evidence-falsification harness, where the whole
    point is to construct states the domain model itself would never
    produce, to prove the READ/inspection/reconciliation layers handle
    them safely regardless."""
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


def _seed_execution_row(
    session_factory, *, execution_id: str, assessment_id: str, status: AssessmentExecutionStatus, version: int = 1
) -> None:
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


def _reconcile_request(execution_id: str) -> ReconcileAssessmentExecutionRequest:
    return ReconcileAssessmentExecutionRequest(
        execution_id=execution_id, requesting_user="admin-106", requesting_username="admin"
    )


# ── A REAL, gated scanner - lets a test synchronize "the scanner has
# genuinely been invoked and is still executing" with a concurrent action,
# without any sleep. ────────────────────────────────────────────────────


class _GatedScanner:
    """Blocks inside scan() on a real threading.Event until released.
    Records every invocation with enough detail to satisfy Section 6's
    requirement: invocation count, assessment identity, scanner IDs,
    target, ordering, terminal state (recorded by the caller after
    ``scan()`` returns)."""

    def __init__(self) -> None:
        self.entered = threading.Event()
        self.release = threading.Event()
        self.invocations: list[dict[str, Any]] = []
        self._lock = threading.Lock()

    def scan(self, target: Target, scanner_ids: Any = None) -> list[Finding]:
        with self._lock:
            self.invocations.append({"target": str(target), "scanner_ids": scanner_ids, "order": len(self.invocations)})
        self.entered.set()
        released = self.release.wait(timeout=10)
        if not released:  # pragma: no cover - defensive, would indicate a real test bug
            raise TimeoutError("gated scanner was never released")
        return [Finding.create("SQLi", "injectable param", Severity.CRITICAL)]

    def compatible_scanners(self, target: Target) -> dict[str, str]:
        return {"fake": "Fake Scanner"}

    @property
    def invocation_count(self) -> int:
        with self._lock:
            return len(self.invocations)


class _ImmediateScanner:
    """A non-gated variant for straightforward invocation-count tests."""

    def __init__(self) -> None:
        self.invocation_count = 0
        self._lock = threading.Lock()

    def scan(self, target: Target, scanner_ids: Any = None) -> list[Finding]:
        with self._lock:
            self.invocation_count += 1
        return [Finding.create("SQLi", "injectable param", Severity.CRITICAL)]

    def compatible_scanners(self, target: Target) -> dict[str, str]:
        return {"fake": "Fake Scanner"}


def _seed_authorized_running_assessment(assessment_repo: LegacyAssessmentRepository, assessment_id: str) -> None:
    """Build a real Assessment through the real domain model, already
    RUNNING (matching the exact durable state SubmitAssessment.execute()
    leaves behind right before submitting the background job) - not a
    hand-crafted ORM row, so this exercises the real
    persist_assessment()/assessment_to_orm() path."""
    from kingsec.domain import Assessment
    from kingsec.domain.authorization import Authorization

    a = Assessment(assessment_id=AssessmentId(assessment_id), target=Target("10.0.0.5", TargetType.IP_ADDRESS))
    a.authorize(Authorization("test-admin", datetime.now(UTC), scope="test"))
    a.start()
    assessment_repo.save(a)


# ── Section 10 / Section 6: admin races a GENUINELY executing worker ──────


class TestAdminRacesLiveWorker:
    def test_admin_cannot_reconcile_while_worker_is_genuinely_inside_the_scanner_call(
        self, session_factory, execution_repo: SqlAlchemyAssessmentExecutionRepository, assessment_repo
    ) -> None:
        """Phase 106 Section 10, Scenario 1, proven with the REAL
        _execute_scan() production function genuinely blocked mid-scan
        (not simulated) racing the REAL ReconcileAssessmentExecution use
        case for real. At the instant the admin reads, durable state is
        execution=RUNNING, assessment=RUNNING (not yet terminal - the
        scanner call has not returned) - reconciliation MUST be rejected."""
        assessment_id = "asmt-106-race1"
        _seed_authorized_running_assessment(assessment_repo, assessment_id)
        execution_repo.create_requested(assessment_id)

        scanner = _GatedScanner()
        worker_thread = threading.Thread(
            target=_execute_scan,
            kwargs={
                "assessment_id": AssessmentId(assessment_id),
                "assessments": assessment_repo,
                "scanner": scanner,
                "ai": None,
                "execution_ledger": execution_repo,
            },
        )
        worker_thread.start()

        # Wait for genuine proof the worker reached the scanner call (not
        # a sleep-based guess) - by the established ordering
        # (try_mark_running commits BEFORE the scanner is invoked), the
        # execution row is now durably RUNNING.
        entered = scanner.entered.wait(timeout=10)
        assert entered, "the worker never reached the scanner call - test setup is broken"

        execution = execution_repo.get_by_assessment_id(assessment_id)
        assert execution is not None
        assert execution.status == AssessmentExecutionStatus.RUNNING

        # The Assessment itself must still be RUNNING (not terminal) at
        # this exact instant - the scanner call has not returned.
        loaded = assessment_repo.get(AssessmentId(assessment_id))
        assert loaded.status == AssessmentStatus.RUNNING

        reconcile_use_case = ReconcileAssessmentExecution(execution_repo)
        with pytest.raises(AssessmentExecutionNotReconcilableError):
            reconcile_use_case.execute(_reconcile_request(execution.id))

        # The rejection must not have mutated anything.
        unchanged = execution_repo.get_by_assessment_id(assessment_id)
        assert unchanged is not None
        assert unchanged.status == AssessmentExecutionStatus.RUNNING
        assert unchanged.version == execution.version

        # Release the worker to finish for real.
        scanner.release.set()
        worker_thread.join(timeout=10)

        final_execution = execution_repo.get_by_assessment_id(assessment_id)
        assert final_execution is not None
        assert final_execution.status == AssessmentExecutionStatus.SUCCEEDED
        final_assessment = assessment_repo.get(AssessmentId(assessment_id))
        assert final_assessment.status == AssessmentStatus.COMPLETED
        assert scanner.invocation_count == 1, "the scanner must have been invoked exactly once across this whole test"

        # NOW reconciliation is a safe, idempotent no-op (already terminal).
        result = reconcile_use_case.execute(_reconcile_request(execution.id))
        assert result is not None
        assert result.mutated is False
        assert result.view.execution_status == AssessmentExecutionStatus.SUCCEEDED

    def test_admin_reconciles_safely_the_instant_after_the_worker_actually_finishes(
        self, session_factory, execution_repo: SqlAlchemyAssessmentExecutionRepository, assessment_repo
    ) -> None:
        """Phase 106 Section 10, Scenario 2: execution RUNNING, Assessment
        becomes COMPLETED, admin observes RUNNING+COMPLETED while a worker
        thread is (harmlessly) still inside its own final bookkeeping.
        Proves the admin's reconciliation and the worker's own
        try_mark_succeeded() cannot both land - exactly one write wins,
        and the final state is always correct, never corrupted."""
        assessment_id = "asmt-106-race2"
        _seed_authorized_running_assessment(assessment_repo, assessment_id)
        execution = execution_repo.create_requested(assessment_id)
        claimed = execution_repo.try_claim(execution.id, execution.version)
        assert claimed is not None
        running_v = execution_repo.try_mark_running(execution.id, claimed)
        assert running_v is not None

        # Directly bring the Assessment to COMPLETED via the real domain
        # model + real persistence, simulating "the worker's scan finished
        # and assessment persistence committed" without needing a second
        # gated scanner thread for this scenario.
        loaded = assessment_repo.get(AssessmentId(assessment_id))
        loaded.complete()
        assessment_repo.save(loaded)

        barrier = threading.Barrier(2)
        outcomes: dict[str, object] = {}

        def _worker_finalizes_ledger() -> None:
            repo = SqlAlchemyAssessmentExecutionRepository(session_factory)
            barrier.wait(timeout=5)
            outcomes["worker_won"] = repo.try_mark_succeeded(execution.id, running_v)

        def _admin_reconciles() -> None:
            repo = SqlAlchemyAssessmentExecutionRepository(session_factory)
            use_case = ReconcileAssessmentExecution(repo)
            barrier.wait(timeout=5)
            outcomes["admin_result"] = use_case.execute(_reconcile_request(execution.id))

        t1 = threading.Thread(target=_worker_finalizes_ledger)
        t2 = threading.Thread(target=_admin_reconciles)
        t1.start()
        t2.start()
        t1.join(timeout=10)
        t2.join(timeout=10)

        admin_result = outcomes["admin_result"]
        assert admin_result is not None
        assert admin_result.view.execution_status == AssessmentExecutionStatus.SUCCEEDED  # type: ignore[union-attr]

        final = execution_repo.get_by_assessment_id(assessment_id)
        assert final is not None
        assert final.status == AssessmentExecutionStatus.SUCCEEDED
        assert final.version == running_v + 1, "exactly one of the two racers must have won the write"


# ── Section 6: losing worker cannot reach the scanner (re-verified with
# ordering/target/scanner_ids recorded, per Section 6's explicit
# requirement) ─────────────────────────────────────────────────────────


class TestLosingWorkerCannotReachScanner:
    def test_two_concurrent_execute_scan_calls_only_one_reaches_the_scanner(
        self, session_factory, execution_repo: SqlAlchemyAssessmentExecutionRepository, assessment_repo
    ) -> None:
        assessment_id = "asmt-106-two-workers"
        _seed_authorized_running_assessment(assessment_repo, assessment_id)
        execution_repo.create_requested(assessment_id)

        scanner = _ImmediateScanner()
        barrier = threading.Barrier(2)
        original_try_claim = execution_repo.try_claim

        def _synchronized_try_claim(execution_id: str, expected_version: int) -> int | None:
            barrier.wait(timeout=5)
            return original_try_claim(execution_id, expected_version)

        execution_repo.try_claim = _synchronized_try_claim  # type: ignore[method-assign]

        threads = [
            threading.Thread(
                target=_execute_scan,
                kwargs={
                    "assessment_id": AssessmentId(assessment_id),
                    "assessments": assessment_repo,
                    "scanner": scanner,
                    "ai": None,
                    "execution_ledger": execution_repo,
                },
            )
            for _ in range(2)
        ]
        for t in threads:
            t.start()
        for t in threads:
            t.join(timeout=10)

        assert scanner.invocation_count == 1, (
            f"expected exactly 1 real scanner invocation across 2 concurrent workers for the SAME "
            f"Assessment, observed {scanner.invocation_count} - a losing worker must never reach the scanner"
        )
        final_execution = execution_repo.get_by_assessment_id(assessment_id)
        assert final_execution is not None
        assert final_execution.status == AssessmentExecutionStatus.SUCCEEDED
        final_assessment = assessment_repo.get(AssessmentId(assessment_id))
        assert final_assessment.status == AssessmentStatus.COMPLETED


# ── Section 20: Races D, E (exactly 2 admins) ────────────────────────────


class TestTwoAdminRaces:
    def test_race_d_two_admins_reconcile_the_same_running_plus_completed_execution(
        self, session_factory, execution_repo: SqlAlchemyAssessmentExecutionRepository, assessment_repo
    ) -> None:
        assessment_id = "asmt-106-race-d"
        _seed_authorized_running_assessment(assessment_repo, assessment_id)
        loaded = assessment_repo.get(AssessmentId(assessment_id))
        loaded.complete()
        assessment_repo.save(loaded)

        execution = execution_repo.create_requested(assessment_id)
        claimed = execution_repo.try_claim(execution.id, execution.version)
        assert claimed is not None
        running_v = execution_repo.try_mark_running(execution.id, claimed)
        assert running_v is not None

        barrier = threading.Barrier(2)
        results: list[object] = []
        lock = threading.Lock()

        def _admin() -> None:
            repo = SqlAlchemyAssessmentExecutionRepository(session_factory)
            use_case = ReconcileAssessmentExecution(repo)
            barrier.wait(timeout=5)
            result = use_case.execute(_reconcile_request(execution.id))
            with lock:
                results.append(result)

        threads = [threading.Thread(target=_admin) for _ in range(2)]
        for t in threads:
            t.start()
        for t in threads:
            t.join(timeout=10)

        assert len(results) == 2
        assert all(r is not None for r in results)
        mutated_count = sum(1 for r in results if r.mutated)  # type: ignore[union-attr]
        assert mutated_count == 1
        assert all(r.view.execution_status == AssessmentExecutionStatus.SUCCEEDED for r in results)  # type: ignore[union-attr]
        final = execution_repo.get_by_assessment_id(assessment_id)
        assert final is not None
        assert final.version == running_v + 1

    def test_race_e_two_admins_reconcile_the_same_running_plus_failed_execution(
        self, session_factory, execution_repo: SqlAlchemyAssessmentExecutionRepository, assessment_repo
    ) -> None:
        assessment_id = "asmt-106-race-e"
        _seed_authorized_running_assessment(assessment_repo, assessment_id)
        loaded = assessment_repo.get(AssessmentId(assessment_id))
        loaded.fail("simulated scanner failure")
        assessment_repo.save(loaded)

        execution = execution_repo.create_requested(assessment_id)
        claimed = execution_repo.try_claim(execution.id, execution.version)
        assert claimed is not None
        running_v = execution_repo.try_mark_running(execution.id, claimed)
        assert running_v is not None

        barrier = threading.Barrier(2)
        results: list[object] = []
        lock = threading.Lock()

        def _admin() -> None:
            repo = SqlAlchemyAssessmentExecutionRepository(session_factory)
            use_case = ReconcileAssessmentExecution(repo)
            barrier.wait(timeout=5)
            result = use_case.execute(_reconcile_request(execution.id))
            with lock:
                results.append(result)

        threads = [threading.Thread(target=_admin) for _ in range(2)]
        for t in threads:
            t.start()
        for t in threads:
            t.join(timeout=10)

        mutated_count = sum(1 for r in results if r.mutated)  # type: ignore[union-attr]
        assert mutated_count == 1
        assert all(r.view.execution_status == AssessmentExecutionStatus.FAILED for r in results)  # type: ignore[union-attr]


# ── Section 27: explicit version-attack matrix ──────────────────────────


class TestVersionAttacks:
    def _to_running(self, execution_repo, assessment_id: str) -> tuple[str, int]:
        execution = execution_repo.create_requested(assessment_id)
        claimed = execution_repo.try_claim(execution.id, execution.version)
        assert claimed is not None
        running_v = execution_repo.try_mark_running(execution.id, claimed)
        assert running_v is not None
        return execution.id, running_v

    def test_stale_version_minus_one_cannot_reconcile(
        self, session_factory, execution_repo, assessment_repo
    ) -> None:
        assessment_id = "asmt-106-stale-1"
        _seed_authorized_running_assessment(assessment_repo, assessment_id)
        loaded = assessment_repo.get(AssessmentId(assessment_id))
        loaded.complete()
        assessment_repo.save(loaded)
        execution_id, running_v = self._to_running(execution_repo, assessment_id)

        assert execution_repo.reconcile_terminal_from_evidence(
            execution_id, running_v - 1, AssessmentExecutionStatus.SUCCEEDED
        ) is False
        still_running = execution_repo.get_by_assessment_id(assessment_id)
        assert still_running is not None
        assert still_running.status == AssessmentExecutionStatus.RUNNING

    def test_stale_version_plus_one_cannot_reconcile(
        self, session_factory, execution_repo, assessment_repo
    ) -> None:
        assessment_id = "asmt-106-stale-2"
        _seed_authorized_running_assessment(assessment_repo, assessment_id)
        loaded = assessment_repo.get(AssessmentId(assessment_id))
        loaded.complete()
        assessment_repo.save(loaded)
        execution_id, running_v = self._to_running(execution_repo, assessment_id)

        assert execution_repo.reconcile_terminal_from_evidence(
            execution_id, running_v + 1, AssessmentExecutionStatus.SUCCEEDED
        ) is False
        still_running = execution_repo.get_by_assessment_id(assessment_id)
        assert still_running is not None
        assert still_running.status == AssessmentExecutionStatus.RUNNING

    def test_repeated_same_version_after_first_success_cannot_reconcile_again(
        self, session_factory, execution_repo, assessment_repo
    ) -> None:
        assessment_id = "asmt-106-stale-3"
        _seed_authorized_running_assessment(assessment_repo, assessment_id)
        loaded = assessment_repo.get(AssessmentId(assessment_id))
        loaded.complete()
        assessment_repo.save(loaded)
        execution_id, running_v = self._to_running(execution_repo, assessment_id)

        first = execution_repo.reconcile_terminal_from_evidence(
            execution_id, running_v, AssessmentExecutionStatus.SUCCEEDED
        )
        assert first is True
        # Reusing the SAME (now-stale) version a second time must fail,
        # even though the outcome value would be identical.
        second = execution_repo.reconcile_terminal_from_evidence(
            execution_id, running_v, AssessmentExecutionStatus.SUCCEEDED
        )
        assert second is False


# ── Section 26: terminal-evidence-falsification harness ─────────────────


class TestTerminalEvidenceFalsification:
    """Directly construct durable state combinations the domain model
    itself would never produce (via raw ORM writes, bypassing every
    application-layer guard) and verify the READ (classification) and
    WRITE (reconciliation) layers both handle them safely regardless of
    how they arose."""

    @pytest.mark.parametrize(
        ("exec_status", "assessment_status", "expected_classification"),
        [
            (AssessmentExecutionStatus.RUNNING, "completed", ExecutionClassification.RECONCILABLE),
            (AssessmentExecutionStatus.SUCCEEDED, "running", ExecutionClassification.INCONSISTENT),
            (AssessmentExecutionStatus.FAILED, "completed", ExecutionClassification.INCONSISTENT),
            (AssessmentExecutionStatus.SUCCEEDED, "failed", ExecutionClassification.INCONSISTENT),
            (AssessmentExecutionStatus.RUNNING, "draft", ExecutionClassification.UNRESOLVED),
            (AssessmentExecutionStatus.REQUESTED, "completed", ExecutionClassification.INCONSISTENT),
            (AssessmentExecutionStatus.CLAIMED, "completed", ExecutionClassification.INCONSISTENT),
            (AssessmentExecutionStatus.RUNNING, "cancelled", ExecutionClassification.UNRESOLVED),
        ],
    )
    def test_impossible_combination_is_classified_and_rejected_safely(
        self,
        session_factory,
        execution_repo,
        exec_status: AssessmentExecutionStatus,
        assessment_status: str,
        expected_classification: ExecutionClassification,
    ) -> None:
        assessment_id = f"asmt-falsify-{exec_status.value}-{assessment_status}"
        _seed_assessment_row(session_factory, assessment_id=assessment_id, status=assessment_status)
        _seed_execution_row(
            session_factory, execution_id=f"exec-falsify-{uuid.uuid4().hex}", assessment_id=assessment_id, status=exec_status
        )

        row = execution_repo.get_by_assessment_id(assessment_id)
        assert row is not None
        actual_classification = classify_execution(
            row.status, AssessmentStatus(assessment_status)
        )
        assert actual_classification == expected_classification, (
            f"classify_execution({exec_status.value}, {assessment_status}) returned "
            f"{actual_classification.value}, expected {expected_classification.value}"
        )

        execution_with_context = execution_repo.get_by_id_with_context(row.id)
        assert execution_with_context is not None
        use_case = ReconcileAssessmentExecution(execution_repo)

        if expected_classification == ExecutionClassification.RECONCILABLE:
            result = use_case.execute(_reconcile_request(row.id))
            assert result is not None
            assert result.mutated is True
        else:
            with pytest.raises(AssessmentExecutionNotReconcilableError):
                use_case.execute(_reconcile_request(row.id))
            unchanged = execution_repo.get_by_assessment_id(assessment_id)
            assert unchanged is not None
            assert unchanged.status == exec_status, "an impossible/unsafe combination must never be mutated"
            assert unchanged.version == row.version


# ── Section 25: persistence delete-then-insert concurrent with a read ───


class TestPersistenceDeleteReinsertAttack:
    def test_concurrent_assessment_saves_never_produce_a_transiently_missing_row(
        self, session_factory, assessment_repo, execution_repo
    ) -> None:
        """Assessment persistence is DELETE-then-INSERT within one
        transaction (_operations.persist_assessment, unchanged - verified
        by direct source re-read this phase). A concurrent reader on a
        SEPARATE connection/session must never observe the intermediate
        deleted-but-not-yet-reinserted state. Proven here with real
        repeated concurrent writes racing real repeated concurrent reads
        via the execution ledger's own joined query, which INNER JOINs to
        assessments - if the assessment were ever transiently missing,
        get_by_id_with_context would return None for a row that
        definitely still has a valid execution record."""
        assessment_id = "asmt-106-persist-race"
        _seed_authorized_running_assessment(assessment_repo, assessment_id)
        execution = execution_repo.create_requested(assessment_id)

        iterations = 50
        stop = threading.Event()
        anomalies: list[str] = []
        lock = threading.Lock()

        def _writer() -> None:
            repo = LegacyAssessmentRepository(session_factory)
            for _ in range(iterations):
                a = repo.get(AssessmentId(assessment_id))
                repo.save(a)  # delete-then-insert of the identical state, repeatedly

        def _reader() -> None:
            repo = SqlAlchemyAssessmentExecutionRepository(session_factory)
            while not stop.is_set():
                row = repo.get_by_id_with_context(execution.id)
                if row is None:
                    with lock:
                        anomalies.append("get_by_id_with_context returned None for a live execution row")
                    break

        writer_thread = threading.Thread(target=_writer)
        reader_threads = [threading.Thread(target=_reader) for _ in range(3)]

        writer_thread.start()
        for t in reader_threads:
            t.start()
        writer_thread.join(timeout=30)
        stop.set()
        for t in reader_threads:
            t.join(timeout=10)

        assert anomalies == [], f"observed transient inconsistency during concurrent save/read: {anomalies}"
        final = assessment_repo.get(AssessmentId(assessment_id))
        assert final.status == AssessmentStatus.RUNNING
        final_execution = execution_repo.get_by_assessment_id(assessment_id)
        assert final_execution is not None
        assert final_execution.status == AssessmentExecutionStatus.REQUESTED, "unrelated to the writer, must be untouched"
