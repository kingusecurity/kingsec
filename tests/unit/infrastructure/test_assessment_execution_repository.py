"""KSEC-102-01: SqlAlchemyAssessmentExecutionRepository - the durable,
database-enforced execution ledger underneath SubmitAssessment.

Against a real on-disk SQLite database throughout, mirroring
test_schedule_occurrence_repository.py's own established style: the
security property under test is that UNIQUE(assessment_id) and the
version+status-gated conditional UPDATE are the actual concurrency
arbiters, not application-level check-then-write logic - proven both
functionally and under real concurrency (N threads racing the same claim,
exactly one winner, no time.sleep() anywhere, threading.Barrier only).

Also covers the Phase 102 crash matrix (Cases A-E), the invalid-transition
matrix, terminal immutability, and a real cross-instance "restart"
scenario where no in-memory object is required to reconstruct the
execution record.
"""

from __future__ import annotations

import threading
import uuid
from pathlib import Path

import pytest
from sqlalchemy import create_engine, select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import sessionmaker

from kingsec.application.assessment_execution_ledger import AssessmentExecutionStatus
from kingsec.infrastructure.persistence.models import AssessmentExecutionORM, Base
from kingsec.infrastructure.persistence.repositories.assessment_execution import (
    SqlAlchemyAssessmentExecutionRepository,
)


@pytest.fixture
def engine(tmp_path: Path):
    db_path = tmp_path / f"assessment-execution-{uuid.uuid4().hex}.sqlite3"
    eng = create_engine(f"sqlite:///{db_path}", future=True, connect_args={"timeout": 30})
    Base.metadata.create_all(eng)
    return eng


@pytest.fixture
def session_factory(engine):
    return sessionmaker(bind=engine, expire_on_commit=False, future=True)


@pytest.fixture
def repo(session_factory) -> SqlAlchemyAssessmentExecutionRepository:
    return SqlAlchemyAssessmentExecutionRepository(session_factory)


class TestCreateRequested:
    def test_first_call_creates_a_fresh_requested_row(self, repo: SqlAlchemyAssessmentExecutionRepository) -> None:
        execution = repo.create_requested("asmt-1")
        assert execution.assessment_id == "asmt-1"
        assert execution.status == AssessmentExecutionStatus.REQUESTED
        assert execution.version == 1

    def test_second_call_for_the_same_assessment_returns_the_existing_row_unchanged(
        self, repo: SqlAlchemyAssessmentExecutionRepository
    ) -> None:
        first = repo.create_requested("asmt-1")
        second = repo.create_requested("asmt-1")
        assert second.id == first.id
        assert second.version == first.version
        assert second.status == AssessmentExecutionStatus.REQUESTED

    def test_a_different_assessment_id_succeeds_independently(
        self, repo: SqlAlchemyAssessmentExecutionRepository
    ) -> None:
        first = repo.create_requested("asmt-1")
        second = repo.create_requested("asmt-2")
        assert first.id != second.id

    def test_unique_constraint_is_enforced_at_the_database_level_not_only_in_application_code(
        self, session_factory
    ) -> None:
        """KSEC-102-01 Step 23: two bare INSERTs for the same assessment_id,
        bypassing the repository's own ON CONFLICT DO NOTHING, must still
        be rejected by the database - proving the constraint, not the
        repository's courtesy, is the real arbiter."""
        with session_factory() as session:
            session.add(
                AssessmentExecutionORM(
                    id="exec-a",
                    assessment_id="asmt-dup",
                    status=AssessmentExecutionStatus.REQUESTED.value,
                    version=1,
                    created_at="2026-09-06T00:00:00",
                    updated_at="2026-09-06T00:00:00",
                )
            )
            session.commit()

            session.add(
                AssessmentExecutionORM(
                    id="exec-b",
                    assessment_id="asmt-dup",
                    status=AssessmentExecutionStatus.REQUESTED.value,
                    version=1,
                    created_at="2026-09-06T00:00:01",
                    updated_at="2026-09-06T00:00:01",
                )
            )
            with pytest.raises(IntegrityError):
                session.commit()

    def test_n_concurrent_create_attempts_produce_exactly_one_row(self, session_factory) -> None:
        """KSEC-102-01 Step 23: real concurrency, real database, no sleeps -
        N threads all attempt create_requested() for the identical
        assessment_id at the same instant (gated by a Barrier)."""
        attempt_count = 8
        barrier = threading.Barrier(attempt_count)
        results: list[str] = []
        lock = threading.Lock()

        def _attempt() -> None:
            repo = SqlAlchemyAssessmentExecutionRepository(session_factory)
            barrier.wait(timeout=5)
            execution = repo.create_requested("asmt-race")
            with lock:
                results.append(execution.id)

        threads = [threading.Thread(target=_attempt) for _ in range(attempt_count)]
        for t in threads:
            t.start()
        for t in threads:
            t.join(timeout=10)

        assert len(results) == attempt_count
        assert len(set(results)) == 1, "every concurrent creator must observe the SAME single execution row"

        with session_factory() as session:
            rows = (
                session.execute(select(AssessmentExecutionORM).where(AssessmentExecutionORM.assessment_id == "asmt-race"))
                .scalars()
                .all()
            )
        assert len(rows) == 1


class TestGetByAssessmentId:
    def test_returns_none_when_no_execution_exists(self, repo: SqlAlchemyAssessmentExecutionRepository) -> None:
        assert repo.get_by_assessment_id("no-such-assessment") is None

    def test_returns_the_current_row_when_one_exists(self, repo: SqlAlchemyAssessmentExecutionRepository) -> None:
        created = repo.create_requested("asmt-1")
        fetched = repo.get_by_assessment_id("asmt-1")
        assert fetched is not None
        assert fetched.id == created.id
        assert fetched.status == AssessmentExecutionStatus.REQUESTED


class TestClaimAndRunningTransitions:
    def test_try_claim_succeeds_from_requested(self, repo: SqlAlchemyAssessmentExecutionRepository) -> None:
        execution = repo.create_requested("asmt-1")
        claimed = repo.try_claim(execution.id, execution.version)
        assert claimed == execution.version + 1

    def test_try_claim_fails_against_a_stale_version(self, repo: SqlAlchemyAssessmentExecutionRepository) -> None:
        """KSEC-102-01 Step 24 (version race): a stale writer using an
        already-superseded version must fail, and must not be able to
        continue on to RUNNING."""
        execution = repo.create_requested("asmt-1")
        repo.try_claim(execution.id, execution.version)  # advances version
        stale_retry = repo.try_claim(execution.id, execution.version)  # same stale version again
        assert stale_retry is None

        # The stale writer must not be able to proceed to RUNNING either,
        # since it never obtained a valid claimed version.
        still_stale = repo.try_mark_running(execution.id, execution.version)
        assert still_stale is None

    def test_try_mark_running_succeeds_from_claimed(self, repo: SqlAlchemyAssessmentExecutionRepository) -> None:
        execution = repo.create_requested("asmt-1")
        claimed_version = repo.try_claim(execution.id, execution.version)
        assert claimed_version is not None
        running_version = repo.try_mark_running(execution.id, claimed_version)
        assert running_version == claimed_version + 1

    def test_n_concurrent_claim_attempts_produce_exactly_one_winner(self, session_factory) -> None:
        """KSEC-102-01 Step 21 Case F / Step 22: real on-disk SQLite, real
        independent repository/session instances, real concurrent threads,
        barrier synchronization, no sleeps. Exactly one of N concurrent
        REQUESTED -> CLAIMED attempts against the SAME execution record may
        win; every other must lose atomically."""
        repo_seed = SqlAlchemyAssessmentExecutionRepository(session_factory)
        execution = repo_seed.create_requested("asmt-race-claim")

        def _attempt(
            execution_id: str,
            version: int,
            barrier: threading.Barrier,
            lock: threading.Lock,
            results: list[int | None],
        ) -> None:
            repo = SqlAlchemyAssessmentExecutionRepository(session_factory)
            barrier.wait(timeout=5)
            claimed = repo.try_claim(execution_id, version)
            with lock:
                results.append(claimed)

        for attempt_count in (8, 8, 8, 8, 8):  # 5 repetitions (Step 22 minimum)
            # Reset to a fresh REQUESTED execution for each repetition so
            # every repetition exercises a genuine race, not a rerun
            # against an already-CLAIMED row.
            fresh = repo_seed.create_requested(f"asmt-race-claim-{uuid.uuid4().hex}")
            barrier = threading.Barrier(attempt_count)
            results: list[int | None] = []
            lock = threading.Lock()

            threads = [
                threading.Thread(target=_attempt, args=(fresh.id, fresh.version, barrier, lock, results))
                for _ in range(attempt_count)
            ]
            for t in threads:
                t.start()
            for t in threads:
                t.join(timeout=10)

            winners = [r for r in results if r is not None]
            assert len(winners) == 1, (
                f"{len(winners)} concurrent callers won try_claim() against the same execution record - "
                "expected exactly 1, meaning the scanner would have been invoked more than once"
            )
        assert execution.status == AssessmentExecutionStatus.REQUESTED  # unrelated seed row untouched


class TestTerminalTransitions:
    def _to_running(self, repo: SqlAlchemyAssessmentExecutionRepository, assessment_id: str) -> tuple[str, int]:
        execution = repo.create_requested(assessment_id)
        claimed = repo.try_claim(execution.id, execution.version)
        assert claimed is not None
        running = repo.try_mark_running(execution.id, claimed)
        assert running is not None
        return execution.id, running

    def test_try_mark_succeeded_from_running(self, repo: SqlAlchemyAssessmentExecutionRepository) -> None:
        execution_id, running_version = self._to_running(repo, "asmt-1")
        assert repo.try_mark_succeeded(execution_id, running_version) is True
        final = repo.get_by_assessment_id("asmt-1")
        assert final is not None
        assert final.status == AssessmentExecutionStatus.SUCCEEDED

    def test_try_mark_failed_from_running(self, repo: SqlAlchemyAssessmentExecutionRepository) -> None:
        execution_id, running_version = self._to_running(repo, "asmt-1")
        assert repo.try_mark_failed(execution_id, running_version) is True
        final = repo.get_by_assessment_id("asmt-1")
        assert final is not None
        assert final.status == AssessmentExecutionStatus.FAILED


class TestSafeReconciliation:
    """KSEC-102-01 Step 19 / Phase 101 Section 12, Cases D and E: a stale
    RUNNING execution record may be reconciled ONLY from durable evidence
    (the caller having already confirmed Assessment.status is terminal),
    never from a timeout."""

    def _to_running(self, repo: SqlAlchemyAssessmentExecutionRepository, assessment_id: str) -> tuple[str, int]:
        execution = repo.create_requested(assessment_id)
        claimed = repo.try_claim(execution.id, execution.version)
        assert claimed is not None
        running = repo.try_mark_running(execution.id, claimed)
        assert running is not None
        return execution.id, running

    def test_case_d_running_plus_durable_completion_evidence_reconciles_to_succeeded(
        self, repo: SqlAlchemyAssessmentExecutionRepository
    ) -> None:
        execution_id, running_version = self._to_running(repo, "asmt-1")
        ok = repo.reconcile_terminal_from_evidence(
            execution_id, running_version, AssessmentExecutionStatus.SUCCEEDED
        )
        assert ok is True
        final = repo.get_by_assessment_id("asmt-1")
        assert final is not None
        assert final.status == AssessmentExecutionStatus.SUCCEEDED

    def test_case_e_running_plus_durable_failure_evidence_reconciles_to_failed(
        self, repo: SqlAlchemyAssessmentExecutionRepository
    ) -> None:
        execution_id, running_version = self._to_running(repo, "asmt-1")
        ok = repo.reconcile_terminal_from_evidence(execution_id, running_version, AssessmentExecutionStatus.FAILED)
        assert ok is True
        final = repo.get_by_assessment_id("asmt-1")
        assert final is not None
        assert final.status == AssessmentExecutionStatus.FAILED

    def test_reconcile_rejects_a_non_terminal_outcome(self, repo: SqlAlchemyAssessmentExecutionRepository) -> None:
        execution_id, running_version = self._to_running(repo, "asmt-1")
        with pytest.raises(ValueError):
            repo.reconcile_terminal_from_evidence(
                execution_id, running_version, AssessmentExecutionStatus.CLAIMED
            )

    def test_reconcile_fails_if_status_is_not_running(self, repo: SqlAlchemyAssessmentExecutionRepository) -> None:
        execution = repo.create_requested("asmt-1")  # still REQUESTED
        ok = repo.reconcile_terminal_from_evidence(
            execution.id, execution.version, AssessmentExecutionStatus.SUCCEEDED
        )
        assert ok is False


class TestInvalidTransitions:
    """KSEC-102-01 Step 25: the exact allowed/disallowed matrix must follow
    the implemented state machine - every invalid transition attempted here
    must fail via the normal version/status-mismatch mechanism, never
    silently succeed."""

    def test_requested_to_running_without_claiming_fails(
        self, repo: SqlAlchemyAssessmentExecutionRepository
    ) -> None:
        execution = repo.create_requested("asmt-1")
        assert repo.try_mark_running(execution.id, execution.version) is None

    def test_requested_to_succeeded_fails(self, repo: SqlAlchemyAssessmentExecutionRepository) -> None:
        execution = repo.create_requested("asmt-1")
        assert repo.try_mark_succeeded(execution.id, execution.version) is False

    def test_claimed_to_succeeded_fails(self, repo: SqlAlchemyAssessmentExecutionRepository) -> None:
        execution = repo.create_requested("asmt-1")
        claimed = repo.try_claim(execution.id, execution.version)
        assert claimed is not None
        assert repo.try_mark_succeeded(execution.id, claimed) is False

    def test_succeeded_to_running_fails(self, repo: SqlAlchemyAssessmentExecutionRepository) -> None:
        execution = repo.create_requested("asmt-1")
        claimed = repo.try_claim(execution.id, execution.version)
        running = repo.try_mark_running(execution.id, claimed)
        repo.try_mark_succeeded(execution.id, running)
        final = repo.get_by_assessment_id("asmt-1")
        assert repo.try_mark_running(execution.id, final.version) is None

    def test_failed_to_running_fails(self, repo: SqlAlchemyAssessmentExecutionRepository) -> None:
        execution = repo.create_requested("asmt-1")
        claimed = repo.try_claim(execution.id, execution.version)
        running = repo.try_mark_running(execution.id, claimed)
        repo.try_mark_failed(execution.id, running)
        final = repo.get_by_assessment_id("asmt-1")
        assert repo.try_mark_running(execution.id, final.version) is None

    def test_succeeded_to_failed_fails(self, repo: SqlAlchemyAssessmentExecutionRepository) -> None:
        execution = repo.create_requested("asmt-1")
        claimed = repo.try_claim(execution.id, execution.version)
        running = repo.try_mark_running(execution.id, claimed)
        repo.try_mark_succeeded(execution.id, running)
        final = repo.get_by_assessment_id("asmt-1")
        assert repo.try_mark_failed(execution.id, final.version) is False

    def test_failed_to_succeeded_fails(self, repo: SqlAlchemyAssessmentExecutionRepository) -> None:
        execution = repo.create_requested("asmt-1")
        claimed = repo.try_claim(execution.id, execution.version)
        running = repo.try_mark_running(execution.id, claimed)
        repo.try_mark_failed(execution.id, running)
        final = repo.get_by_assessment_id("asmt-1")
        assert repo.try_mark_succeeded(execution.id, final.version) is False


class TestTerminalImmutability:
    """KSEC-102-01 Step 26: SUCCEEDED and FAILED cannot transition back
    into an active state - a terminal execution record is durable
    evidence."""

    def test_succeeded_record_cannot_be_reclaimed_or_rerun(
        self, repo: SqlAlchemyAssessmentExecutionRepository
    ) -> None:
        execution = repo.create_requested("asmt-1")
        claimed = repo.try_claim(execution.id, execution.version)
        running = repo.try_mark_running(execution.id, claimed)
        repo.try_mark_succeeded(execution.id, running)
        final = repo.get_by_assessment_id("asmt-1")

        assert repo.try_claim(execution.id, final.version) is None
        assert repo.try_mark_running(execution.id, final.version) is None
        assert repo.try_mark_succeeded(execution.id, final.version) is False
        assert repo.try_mark_failed(execution.id, final.version) is False
        assert (
            repo.reconcile_terminal_from_evidence(execution.id, final.version, AssessmentExecutionStatus.FAILED)
            is False
        )

    def test_failed_record_cannot_be_reclaimed_or_rerun(self, repo: SqlAlchemyAssessmentExecutionRepository) -> None:
        execution = repo.create_requested("asmt-1")
        claimed = repo.try_claim(execution.id, execution.version)
        running = repo.try_mark_running(execution.id, claimed)
        repo.try_mark_failed(execution.id, running)
        final = repo.get_by_assessment_id("asmt-1")

        assert repo.try_claim(execution.id, final.version) is None
        assert repo.try_mark_running(execution.id, final.version) is None
        assert repo.try_mark_succeeded(execution.id, final.version) is False
        assert repo.try_mark_failed(execution.id, final.version) is False


class TestCrashMatrix:
    """KSEC-102-01 Step 21: durable state observed after each crash-
    equivalent window, proven by simply never calling the next transition -
    the durable row is inspected exactly as a fresh process/worker would
    see it after an unclean termination."""

    def test_case_a_requested_crash_leaves_execution_durably_requested(
        self, repo: SqlAlchemyAssessmentExecutionRepository
    ) -> None:
        repo.create_requested("asmt-a")
        observed = repo.get_by_assessment_id("asmt-a")
        assert observed is not None
        assert observed.status == AssessmentExecutionStatus.REQUESTED

    def test_case_b_claimed_crash_leaves_execution_durably_claimed(
        self, repo: SqlAlchemyAssessmentExecutionRepository
    ) -> None:
        execution = repo.create_requested("asmt-b")
        repo.try_claim(execution.id, execution.version)
        observed = repo.get_by_assessment_id("asmt-b")
        assert observed is not None
        assert observed.status == AssessmentExecutionStatus.CLAIMED

    def test_case_c_running_crash_leaves_execution_durably_running(
        self, repo: SqlAlchemyAssessmentExecutionRepository
    ) -> None:
        execution = repo.create_requested("asmt-c")
        claimed = repo.try_claim(execution.id, execution.version)
        repo.try_mark_running(execution.id, claimed)
        observed = repo.get_by_assessment_id("asmt-c")
        assert observed is not None
        assert observed.status == AssessmentExecutionStatus.RUNNING

    def test_case_d_running_plus_durable_completion_evidence(
        self, repo: SqlAlchemyAssessmentExecutionRepository
    ) -> None:
        execution = repo.create_requested("asmt-d")
        claimed = repo.try_claim(execution.id, execution.version)
        running = repo.try_mark_running(execution.id, claimed)
        assert repo.reconcile_terminal_from_evidence(
            execution.id, running, AssessmentExecutionStatus.SUCCEEDED
        )
        observed = repo.get_by_assessment_id("asmt-d")
        assert observed.status == AssessmentExecutionStatus.SUCCEEDED

    def test_case_e_running_plus_durable_failure_evidence(
        self, repo: SqlAlchemyAssessmentExecutionRepository
    ) -> None:
        execution = repo.create_requested("asmt-e")
        claimed = repo.try_claim(execution.id, execution.version)
        running = repo.try_mark_running(execution.id, claimed)
        assert repo.reconcile_terminal_from_evidence(execution.id, running, AssessmentExecutionStatus.FAILED)
        observed = repo.get_by_assessment_id("asmt-e")
        assert observed.status == AssessmentExecutionStatus.FAILED


class TestRestart:
    """KSEC-102-01 Step 27: a completely fresh engine/session_factory/
    repository instance against the SAME on-disk database file must see
    the durable execution record - no in-memory object may be required to
    reconstruct it."""

    def test_execution_record_survives_a_fresh_repository_instance_against_the_same_database(
        self, tmp_path: Path
    ) -> None:
        db_path = tmp_path / f"restart-{uuid.uuid4().hex}.sqlite3"
        db_url = f"sqlite:///{db_path}"

        engine_1 = create_engine(db_url, future=True, connect_args={"timeout": 30})
        Base.metadata.create_all(engine_1)
        session_factory_1 = sessionmaker(bind=engine_1, expire_on_commit=False, future=True)
        repo_1 = SqlAlchemyAssessmentExecutionRepository(session_factory_1)

        execution = repo_1.create_requested("asmt-restart")
        claimed = repo_1.try_claim(execution.id, execution.version)
        running_version = repo_1.try_mark_running(execution.id, claimed)
        engine_1.dispose()
        del engine_1, session_factory_1, repo_1

        # A completely fresh engine/session_factory/repository triple,
        # sharing no Python object with the ones above - only the on-disk
        # file - simulating a process restart.
        engine_2 = create_engine(db_url, future=True, connect_args={"timeout": 30})
        session_factory_2 = sessionmaker(bind=engine_2, expire_on_commit=False, future=True)
        repo_2 = SqlAlchemyAssessmentExecutionRepository(session_factory_2)

        observed = repo_2.get_by_assessment_id("asmt-restart")
        assert observed is not None
        assert observed.id == execution.id
        assert observed.status == AssessmentExecutionStatus.RUNNING
        assert observed.version == running_version

        # The "restarted" repository can still safely continue the
        # lifecycle using purely durable state - no in-memory object from
        # the first instance was required.
        assert repo_2.try_mark_succeeded(observed.id, observed.version) is True
        engine_2.dispose()
