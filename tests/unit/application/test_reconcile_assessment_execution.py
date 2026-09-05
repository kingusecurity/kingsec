"""KSEC-105-01: ReconcileAssessmentExecution - explicit, evidence-gated,
ADMIN-only terminal ledger reconciliation.

Real on-disk SQLite + the real SqlAlchemyAssessmentExecutionRepository
throughout (KSEC-105-01 Step 25: "do not merely mock repository calls") -
seeded directly via the ORM classes, the same style already established in
test_assessment_execution_inspection.py.
"""

from __future__ import annotations

import threading
import uuid
from datetime import UTC, datetime
from pathlib import Path

import pytest
from sqlalchemy import create_engine, delete
from sqlalchemy.orm import sessionmaker

from kingsec.application.assessment_execution_ledger import AssessmentExecutionStatus
from kingsec.application.errors import AssessmentExecutionNotReconcilableError
from kingsec.application.use_cases.execution_inspection_dto import ReconcileAssessmentExecutionRequest
from kingsec.application.use_cases.reconcile_assessment_execution import ReconcileAssessmentExecution
from kingsec.infrastructure.persistence.models import (
    AssessmentExecutionORM,
    AssessmentORM,
    Base,
)
from kingsec.infrastructure.persistence.repositories.assessment_execution import (
    SqlAlchemyAssessmentExecutionRepository,
)


@pytest.fixture
def engine(tmp_path: Path):
    db_path = tmp_path / f"reconcile-{uuid.uuid4().hex}.sqlite3"
    eng = create_engine(f"sqlite:///{db_path}", future=True, connect_args={"timeout": 30})
    Base.metadata.create_all(eng)
    return eng


@pytest.fixture
def session_factory(engine):
    return sessionmaker(bind=engine, expire_on_commit=False, future=True)


@pytest.fixture
def repo(session_factory) -> SqlAlchemyAssessmentExecutionRepository:
    return SqlAlchemyAssessmentExecutionRepository(session_factory)


@pytest.fixture
def use_case(repo: SqlAlchemyAssessmentExecutionRepository) -> ReconcileAssessmentExecution:
    return ReconcileAssessmentExecution(repo)


def _now() -> str:
    return datetime.now(UTC).isoformat()


def _seed_assessment(session_factory, *, assessment_id: str, status: str) -> None:
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


def _seed_execution(
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


def _make_request(execution_id: str) -> ReconcileAssessmentExecutionRequest:
    return ReconcileAssessmentExecutionRequest(
        execution_id=execution_id, requesting_user="admin-1", requesting_username="admin"
    )


class TestNotFound:
    def test_unknown_execution_id_returns_none(self, use_case: ReconcileAssessmentExecution) -> None:
        assert use_case.execute(_make_request("no-such-execution")) is None

    def test_running_with_deleted_assessment_is_not_found(
        self, session_factory, repo, use_case: ReconcileAssessmentExecution
    ) -> None:
        """Phase 105 Test 12 (RUNNING + missing Assessment): the joined
        query is an INNER join, so an execution whose linked Assessment
        row no longer exists is simply not found - fails closed as a 404,
        not silently treated as reconcilable."""
        _seed_assessment(session_factory, assessment_id="asmt-orphan", status="running")
        execution = repo.create_requested("asmt-orphan")
        claimed = repo.try_claim(execution.id, execution.version)
        repo.try_mark_running(execution.id, claimed)

        with session_factory() as session:
            session.execute(delete(AssessmentORM).where(AssessmentORM.id == "asmt-orphan"))
            session.commit()

        assert use_case.execute(_make_request(execution.id)) is None


class TestValidReconciliation:
    def test_running_plus_completed_reconciles_to_succeeded(
        self, session_factory, repo, use_case: ReconcileAssessmentExecution
    ) -> None:
        _seed_assessment(session_factory, assessment_id="asmt-1", status="completed")
        execution = repo.create_requested("asmt-1")
        claimed = repo.try_claim(execution.id, execution.version)
        repo.try_mark_running(execution.id, claimed)

        result = use_case.execute(_make_request(execution.id))
        assert result is not None
        assert result.mutated is True
        assert result.previous_execution_status == AssessmentExecutionStatus.RUNNING
        assert result.view.execution_status == AssessmentExecutionStatus.SUCCEEDED

        final = repo.get_by_assessment_id("asmt-1")
        assert final is not None
        assert final.status == AssessmentExecutionStatus.SUCCEEDED

    def test_running_plus_failed_reconciles_to_failed(
        self, session_factory, repo, use_case: ReconcileAssessmentExecution
    ) -> None:
        _seed_assessment(session_factory, assessment_id="asmt-2", status="failed")
        execution = repo.create_requested("asmt-2")
        claimed = repo.try_claim(execution.id, execution.version)
        repo.try_mark_running(execution.id, claimed)

        result = use_case.execute(_make_request(execution.id))
        assert result is not None
        assert result.mutated is True
        assert result.view.execution_status == AssessmentExecutionStatus.FAILED

        final = repo.get_by_assessment_id("asmt-2")
        assert final is not None
        assert final.status == AssessmentExecutionStatus.FAILED

    def test_outcome_is_never_taken_from_the_request(self, session_factory, repo) -> None:
        """KSEC-105-01 Step 5: ReconcileAssessmentExecutionRequest has no
        field capable of selecting an outcome - this is a structural
        proof, not merely a behavioral one: constructing the request
        with only execution_id/attribution fields and observing the
        correct, evidence-derived outcome anyway is the test."""
        _seed_assessment(session_factory, assessment_id="asmt-3", status="completed")
        execution = repo.create_requested("asmt-3")
        claimed = repo.try_claim(execution.id, execution.version)
        repo.try_mark_running(execution.id, claimed)

        request = ReconcileAssessmentExecutionRequest(execution_id=execution.id)
        assert not hasattr(request, "status")
        assert not hasattr(request, "outcome")
        assert not hasattr(request, "force")

        use_case = ReconcileAssessmentExecution(repo)
        result = use_case.execute(request)
        assert result is not None
        assert result.view.execution_status == AssessmentExecutionStatus.SUCCEEDED


class TestIdempotency:
    def test_second_call_on_already_succeeded_does_not_mutate(
        self, session_factory, repo, use_case: ReconcileAssessmentExecution
    ) -> None:
        _seed_assessment(session_factory, assessment_id="asmt-4", status="completed")
        execution = repo.create_requested("asmt-4")
        claimed = repo.try_claim(execution.id, execution.version)
        repo.try_mark_running(execution.id, claimed)

        first = use_case.execute(_make_request(execution.id))
        assert first is not None
        assert first.mutated is True
        version_after_first = first.view.execution_version

        second = use_case.execute(_make_request(execution.id))
        assert second is not None
        assert second.mutated is False
        assert second.view.execution_status == AssessmentExecutionStatus.SUCCEEDED
        assert second.view.execution_version == version_after_first, "a no-op reconciliation must not bump version"

    def test_second_call_on_already_failed_does_not_mutate(
        self, session_factory, repo, use_case: ReconcileAssessmentExecution
    ) -> None:
        _seed_assessment(session_factory, assessment_id="asmt-5", status="failed")
        execution = repo.create_requested("asmt-5")
        claimed = repo.try_claim(execution.id, execution.version)
        repo.try_mark_running(execution.id, claimed)

        use_case.execute(_make_request(execution.id))
        second = use_case.execute(_make_request(execution.id))
        assert second is not None
        assert second.mutated is False
        assert second.view.execution_status == AssessmentExecutionStatus.FAILED


class TestInvalidEvidenceRejectedWithoutMutation:
    def test_requested_is_rejected(self, session_factory, repo, use_case: ReconcileAssessmentExecution) -> None:
        _seed_assessment(session_factory, assessment_id="asmt-6", status="completed")
        execution = repo.create_requested("asmt-6")
        with pytest.raises(AssessmentExecutionNotReconcilableError):
            use_case.execute(_make_request(execution.id))
        unchanged = repo.get_by_assessment_id("asmt-6")
        assert unchanged is not None
        assert unchanged.status == AssessmentExecutionStatus.REQUESTED
        assert unchanged.version == execution.version

    def test_claimed_is_rejected(self, session_factory, repo, use_case: ReconcileAssessmentExecution) -> None:
        _seed_assessment(session_factory, assessment_id="asmt-7", status="completed")
        execution = repo.create_requested("asmt-7")
        claimed_version = repo.try_claim(execution.id, execution.version)
        with pytest.raises(AssessmentExecutionNotReconcilableError):
            use_case.execute(_make_request(execution.id))
        unchanged = repo.get_by_assessment_id("asmt-7")
        assert unchanged is not None
        assert unchanged.status == AssessmentExecutionStatus.CLAIMED
        assert unchanged.version == claimed_version

    def test_running_plus_authorized_is_rejected(
        self, session_factory, repo, use_case: ReconcileAssessmentExecution
    ) -> None:
        _seed_assessment(session_factory, assessment_id="asmt-8", status="authorized")
        execution = repo.create_requested("asmt-8")
        claimed = repo.try_claim(execution.id, execution.version)
        repo.try_mark_running(execution.id, claimed)
        with pytest.raises(AssessmentExecutionNotReconcilableError):
            use_case.execute(_make_request(execution.id))
        unchanged = repo.get_by_assessment_id("asmt-8")
        assert unchanged is not None
        assert unchanged.status == AssessmentExecutionStatus.RUNNING

    def test_running_plus_running_is_rejected(
        self, session_factory, repo, use_case: ReconcileAssessmentExecution
    ) -> None:
        _seed_assessment(session_factory, assessment_id="asmt-9", status="running")
        execution = repo.create_requested("asmt-9")
        claimed = repo.try_claim(execution.id, execution.version)
        repo.try_mark_running(execution.id, claimed)
        with pytest.raises(AssessmentExecutionNotReconcilableError):
            use_case.execute(_make_request(execution.id))
        unchanged = repo.get_by_assessment_id("asmt-9")
        assert unchanged is not None
        assert unchanged.status == AssessmentExecutionStatus.RUNNING

    def test_succeeded_execution_remains_immutable(
        self, session_factory, repo, use_case: ReconcileAssessmentExecution
    ) -> None:
        """Terminal + evidence that would now suggest a DIFFERENT outcome
        (INCONSISTENT) must never be force-corrected."""
        _seed_assessment(session_factory, assessment_id="asmt-10", status="completed")
        execution = repo.create_requested("asmt-10")
        claimed = repo.try_claim(execution.id, execution.version)
        running_v = repo.try_mark_running(execution.id, claimed)
        repo.try_mark_succeeded(execution.id, running_v)

        # Mutate the Assessment's stored status directly to simulate an
        # inconsistent combination (SUCCEEDED execution + non-matching
        # Assessment status) without going through any real code path.
        with session_factory() as session:
            from sqlalchemy import update

            session.execute(update(AssessmentORM).where(AssessmentORM.id == "asmt-10").values(status="FAILED"))
            session.commit()

        with pytest.raises(AssessmentExecutionNotReconcilableError):
            use_case.execute(_make_request(execution.id))
        unchanged = repo.get_by_assessment_id("asmt-10")
        assert unchanged is not None
        assert unchanged.status == AssessmentExecutionStatus.SUCCEEDED, "terminal execution must remain immutable"

    def test_failed_execution_remains_immutable(
        self, session_factory, repo, use_case: ReconcileAssessmentExecution
    ) -> None:
        _seed_assessment(session_factory, assessment_id="asmt-11", status="failed")
        execution = repo.create_requested("asmt-11")
        claimed = repo.try_claim(execution.id, execution.version)
        running_v = repo.try_mark_running(execution.id, claimed)
        repo.try_mark_failed(execution.id, running_v)

        result = use_case.execute(_make_request(execution.id))
        # FAILED execution + matching FAILED assessment = TERMINAL,
        # classified as an idempotent no-op success, not an error - but
        # still zero mutation.
        assert result is not None
        assert result.mutated is False
        unchanged = repo.get_by_assessment_id("asmt-11")
        assert unchanged is not None
        assert unchanged.status == AssessmentExecutionStatus.FAILED

    def test_inconsistent_succeeded_plus_running_is_rejected(
        self, session_factory, repo, use_case: ReconcileAssessmentExecution
    ) -> None:
        _seed_assessment(session_factory, assessment_id="asmt-12", status="running")
        execution = repo.create_requested("asmt-12")
        claimed = repo.try_claim(execution.id, execution.version)
        running_v = repo.try_mark_running(execution.id, claimed)
        repo.try_mark_succeeded(execution.id, running_v)

        with pytest.raises(AssessmentExecutionNotReconcilableError):
            use_case.execute(_make_request(execution.id))


class TestConcurrency:
    """KSEC-105-01 Step 25: real database, real threads, threading.Barrier,
    no sleeps."""

    def test_n_concurrent_reconciliation_attempts_produce_exactly_one_transition(self, session_factory) -> None:
        repo_seed = SqlAlchemyAssessmentExecutionRepository(session_factory)
        _seed_assessment(session_factory, assessment_id="asmt-race", status="completed")
        execution = repo_seed.create_requested("asmt-race")
        claimed = repo_seed.try_claim(execution.id, execution.version)
        running_v = repo_seed.try_mark_running(execution.id, claimed)
        assert running_v is not None

        attempt_count = 8
        barrier = threading.Barrier(attempt_count)
        results: list[object] = []
        lock = threading.Lock()

        def _attempt() -> None:
            repo = SqlAlchemyAssessmentExecutionRepository(session_factory)
            use_case = ReconcileAssessmentExecution(repo)
            barrier.wait(timeout=5)
            result = use_case.execute(_make_request(execution.id))
            with lock:
                results.append(result)

        threads = [threading.Thread(target=_attempt) for _ in range(attempt_count)]
        for t in threads:
            t.start()
        for t in threads:
            t.join(timeout=10)

        assert len(results) == attempt_count
        assert all(r is not None for r in results)
        mutated_count = sum(1 for r in results if r.mutated)  # type: ignore[union-attr]
        assert mutated_count == 1, f"expected exactly 1 concurrent caller to perform the mutation, got {mutated_count}"
        assert all(r.view.execution_status == AssessmentExecutionStatus.SUCCEEDED for r in results)  # type: ignore[union-attr]

        final_repo = SqlAlchemyAssessmentExecutionRepository(session_factory)
        final = final_repo.get_by_assessment_id("asmt-race")
        assert final is not None
        assert final.status == AssessmentExecutionStatus.SUCCEEDED
        assert final.version == running_v + 1, "exactly one version bump must have occurred, not eight"

    def test_admin_races_worker_transition_stale_version_cannot_overwrite_newer_state(self, session_factory) -> None:
        """Race 1/2 from Phase 105 Step 13: the 'worker' legitimately
        completes the execution via its own try_mark_succeeded() call
        concurrently with an admin's reconciliation attempt using a
        version already stale by the time it writes."""
        repo_seed = SqlAlchemyAssessmentExecutionRepository(session_factory)
        _seed_assessment(session_factory, assessment_id="asmt-worker-race", status="completed")
        execution = repo_seed.create_requested("asmt-worker-race")
        claimed = repo_seed.try_claim(execution.id, execution.version)
        running_v = repo_seed.try_mark_running(execution.id, claimed)

        barrier = threading.Barrier(2)
        outcomes: dict[str, object] = {}

        def _worker() -> None:
            repo = SqlAlchemyAssessmentExecutionRepository(session_factory)
            barrier.wait(timeout=5)
            outcomes["worker_won"] = repo.try_mark_succeeded(execution.id, running_v)

        def _admin() -> None:
            repo = SqlAlchemyAssessmentExecutionRepository(session_factory)
            use_case = ReconcileAssessmentExecution(repo)
            barrier.wait(timeout=5)
            outcomes["admin_result"] = use_case.execute(_make_request(execution.id))

        t1 = threading.Thread(target=_worker)
        t2 = threading.Thread(target=_admin)
        t1.start()
        t2.start()
        t1.join(timeout=10)
        t2.join(timeout=10)

        admin_result = outcomes["admin_result"]
        assert admin_result is not None
        # Whichever one actually performed the write, the final state must
        # be SUCCEEDED and the admin's reported view must match it - never
        # a stale/incorrect report.
        assert admin_result.view.execution_status == AssessmentExecutionStatus.SUCCEEDED  # type: ignore[union-attr]

        final_repo = SqlAlchemyAssessmentExecutionRepository(session_factory)
        final = final_repo.get_by_assessment_id("asmt-worker-race")
        assert final is not None
        assert final.status == AssessmentExecutionStatus.SUCCEEDED
        assert final.version == running_v + 1, "exactly one of the two racers' writes must have landed, not both"
