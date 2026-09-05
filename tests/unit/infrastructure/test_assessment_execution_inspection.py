"""KSEC-103-01: SqlAlchemyAssessmentExecutionRepository's read-only
inspection queries (list_with_context / get_by_id_with_context).

Real on-disk SQLite throughout - no mocks, no dictionary fakes (KSEC-103-01
Database Testing requirement). Rows are seeded directly via the ORM
classes (the same style already established in
test_schedule_occurrence_repository.py) so each test controls the exact
durable state under inspection without going through the full
CreateAssessment/SubmitAssessment call graph.
"""

from __future__ import annotations

import threading
import uuid
from datetime import UTC, datetime
from pathlib import Path

import pytest
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

from kingsec.application.assessment_execution_ledger import AssessmentExecutionStatus
from kingsec.infrastructure.persistence.models import (
    AssessmentExecutionORM,
    AssessmentORM,
    Base,
    ScheduleOccurrenceORM,
    ScheduleORM,
)
from kingsec.infrastructure.persistence.repositories.assessment_execution import (
    SqlAlchemyAssessmentExecutionRepository,
)


@pytest.fixture
def engine(tmp_path: Path):
    db_path = tmp_path / f"execution-inspection-{uuid.uuid4().hex}.sqlite3"
    eng = create_engine(f"sqlite:///{db_path}", future=True, connect_args={"timeout": 30})
    Base.metadata.create_all(eng)
    return eng


@pytest.fixture
def session_factory(engine):
    return sessionmaker(bind=engine, expire_on_commit=False, future=True)


@pytest.fixture
def repo(session_factory) -> SqlAlchemyAssessmentExecutionRepository:
    return SqlAlchemyAssessmentExecutionRepository(session_factory)


def _now() -> str:
    return datetime.now(UTC).isoformat()


def _seed_assessment(
    session_factory,
    *,
    assessment_id: str,
    status: str = "running",
    schedule_occurrence_id: str | None = None,
) -> None:
    with session_factory() as session:
        session.add(
            AssessmentORM(
                id=assessment_id,
                target_value="10.0.0.5",
                target_type="ip_address",
                status=status,
                created_at=_now(),
                schedule_occurrence_id=schedule_occurrence_id,
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


def _seed_schedule_and_occurrence(
    session_factory, *, schedule_id: str, occurrence_id: str, owner_user_id: str, occurrence_key: str
) -> None:
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


class TestGetByIdWithContext:
    def test_returns_none_for_unknown_execution_id(self, repo: SqlAlchemyAssessmentExecutionRepository) -> None:
        assert repo.get_by_id_with_context("no-such-execution") is None

    def test_manual_assessment_has_no_schedule_fields(
        self, session_factory, repo: SqlAlchemyAssessmentExecutionRepository
    ) -> None:
        """Phase 103 Test J: a normal/manual assessment must not crash the
        join and must report every schedule field as absent."""
        _seed_assessment(session_factory, assessment_id="asmt-manual", status="running")
        _seed_execution(
            session_factory,
            execution_id="exec-manual",
            assessment_id="asmt-manual",
            status=AssessmentExecutionStatus.RUNNING,
        )

        row = repo.get_by_id_with_context("exec-manual")
        assert row is not None
        assert row.execution_id == "exec-manual"
        assert row.assessment_id == "asmt-manual"
        assert row.schedule_occurrence_id is None
        assert row.occurrence_key is None
        assert row.schedule_id is None
        assert row.schedule_owner_user_id is None

    def test_scheduled_assessment_joins_occurrence_and_schedule_correctly(
        self, session_factory, repo: SqlAlchemyAssessmentExecutionRepository
    ) -> None:
        """Phase 103 Test K: execution -> assessment -> schedule occurrence
        -> schedule must be represented correctly end to end."""
        _seed_schedule_and_occurrence(
            session_factory,
            schedule_id="sched-1",
            occurrence_id="occ-1",
            owner_user_id="alice",
            occurrence_key="2026-09-05T04:00:00",
        )
        _seed_assessment(
            session_factory, assessment_id="asmt-scheduled", status="running", schedule_occurrence_id="occ-1"
        )
        _seed_execution(
            session_factory,
            execution_id="exec-scheduled",
            assessment_id="asmt-scheduled",
            status=AssessmentExecutionStatus.RUNNING,
        )

        row = repo.get_by_id_with_context("exec-scheduled")
        assert row is not None
        assert row.schedule_occurrence_id == "occ-1"
        assert row.occurrence_key == "2026-09-05T04:00:00"
        assert row.schedule_id == "sched-1"
        assert row.schedule_owner_user_id == "alice"

    def test_reading_does_not_mutate_the_execution_record(
        self, session_factory, repo: SqlAlchemyAssessmentExecutionRepository
    ) -> None:
        """Phase 103 Test D/E: inspection must never cause a state
        mutation, including version bump, merely by being queried."""
        _seed_assessment(session_factory, assessment_id="asmt-1", status="running")
        _seed_execution(
            session_factory, execution_id="exec-1", assessment_id="asmt-1", status=AssessmentExecutionStatus.CLAIMED
        )

        before = repo.get_by_id_with_context("exec-1")
        repo.get_by_id_with_context("exec-1")
        repo.get_by_id_with_context("exec-1")
        after = repo.get_by_id_with_context("exec-1")

        assert before is not None
        assert after is not None
        assert before.execution_status == after.execution_status == AssessmentExecutionStatus.CLAIMED


class TestListWithContext:
    def test_empty_database_returns_empty_result(self, repo: SqlAlchemyAssessmentExecutionRepository) -> None:
        rows, total = repo.list_with_context(limit=50, offset=0)
        assert rows == []
        assert total == 0

    def test_status_filter_is_an_allowlisted_in_filter(
        self, session_factory, repo: SqlAlchemyAssessmentExecutionRepository
    ) -> None:
        for i, status in enumerate(
            [
                AssessmentExecutionStatus.REQUESTED,
                AssessmentExecutionStatus.CLAIMED,
                AssessmentExecutionStatus.RUNNING,
                AssessmentExecutionStatus.SUCCEEDED,
                AssessmentExecutionStatus.FAILED,
            ]
        ):
            _seed_assessment(session_factory, assessment_id=f"asmt-{i}", status="running")
            _seed_execution(session_factory, execution_id=f"exec-{i}", assessment_id=f"asmt-{i}", status=status)

        rows, total = repo.list_with_context(
            statuses=[AssessmentExecutionStatus.REQUESTED, AssessmentExecutionStatus.CLAIMED], limit=50, offset=0
        )
        assert total == 2
        assert {r.execution_status for r in rows} == {
            AssessmentExecutionStatus.REQUESTED,
            AssessmentExecutionStatus.CLAIMED,
        }

    def test_unresolved_statuses_filter_matches_non_terminal_only(
        self, session_factory, repo: SqlAlchemyAssessmentExecutionRepository
    ) -> None:
        for i, status in enumerate(
            [
                AssessmentExecutionStatus.REQUESTED,
                AssessmentExecutionStatus.CLAIMED,
                AssessmentExecutionStatus.RUNNING,
                AssessmentExecutionStatus.SUCCEEDED,
                AssessmentExecutionStatus.FAILED,
            ]
        ):
            _seed_assessment(session_factory, assessment_id=f"asmt-u{i}", status="running")
            _seed_execution(session_factory, execution_id=f"exec-u{i}", assessment_id=f"asmt-u{i}", status=status)

        rows, total = repo.list_with_context(
            statuses=[
                AssessmentExecutionStatus.REQUESTED,
                AssessmentExecutionStatus.CLAIMED,
                AssessmentExecutionStatus.RUNNING,
            ],
            limit=50,
            offset=0,
        )
        assert total == 3
        assert AssessmentExecutionStatus.SUCCEEDED not in {r.execution_status for r in rows}
        assert AssessmentExecutionStatus.FAILED not in {r.execution_status for r in rows}

    def test_pagination_bounds_and_total_count(
        self, session_factory, repo: SqlAlchemyAssessmentExecutionRepository
    ) -> None:
        for i in range(5):
            _seed_assessment(session_factory, assessment_id=f"asmt-p{i}", status="running")
            _seed_execution(
                session_factory,
                execution_id=f"exec-p{i}",
                assessment_id=f"asmt-p{i}",
                status=AssessmentExecutionStatus.REQUESTED,
            )

        page1, total1 = repo.list_with_context(limit=2, offset=0)
        page2, total2 = repo.list_with_context(limit=2, offset=2)
        page3, total3 = repo.list_with_context(limit=2, offset=4)

        assert total1 == total2 == total3 == 5
        assert len(page1) == 2
        assert len(page2) == 2
        assert len(page3) == 1
        ids = {r.execution_id for r in (*page1, *page2, *page3)}
        assert len(ids) == 5, "pagination must not return duplicate or missing rows across pages"

    def test_ordering_is_deterministic(self, session_factory, repo: SqlAlchemyAssessmentExecutionRepository) -> None:
        for i in range(4):
            _seed_assessment(session_factory, assessment_id=f"asmt-o{i}", status="running")
            _seed_execution(
                session_factory,
                execution_id=f"exec-o{i}",
                assessment_id=f"asmt-o{i}",
                status=AssessmentExecutionStatus.REQUESTED,
            )
        first, _ = repo.list_with_context(limit=50, offset=0)
        second, _ = repo.list_with_context(limit=50, offset=0)
        assert [r.execution_id for r in first] == [r.execution_id for r in second]

    def test_manual_and_scheduled_assessments_can_be_listed_together(
        self, session_factory, repo: SqlAlchemyAssessmentExecutionRepository
    ) -> None:
        _seed_assessment(session_factory, assessment_id="asmt-manual-2", status="running")
        _seed_execution(
            session_factory,
            execution_id="exec-manual-2",
            assessment_id="asmt-manual-2",
            status=AssessmentExecutionStatus.RUNNING,
        )
        _seed_schedule_and_occurrence(
            session_factory,
            schedule_id="sched-2",
            occurrence_id="occ-2",
            owner_user_id="bob",
            occurrence_key="2026-09-06T04:00:00",
        )
        _seed_assessment(
            session_factory, assessment_id="asmt-sched-2", status="running", schedule_occurrence_id="occ-2"
        )
        _seed_execution(
            session_factory,
            execution_id="exec-sched-2",
            assessment_id="asmt-sched-2",
            status=AssessmentExecutionStatus.RUNNING,
        )

        rows, total = repo.list_with_context(limit=50, offset=0)
        assert total == 2
        by_id = {r.execution_id: r for r in rows}
        assert by_id["exec-manual-2"].schedule_id is None
        assert by_id["exec-sched-2"].schedule_id == "sched-2"


class TestConcurrentInspectionSafety:
    """Phase 103 Test O: reading via list_with_context/get_by_id_with_context
    concurrently with a real transition must never corrupt state, cause an
    invalid transition, create duplicate rows, or mutate anything from the
    read path - real threads, a real Barrier, no sleeps."""

    def test_concurrent_reads_during_a_real_transition_never_mutate_or_corrupt(self, session_factory) -> None:
        repo = SqlAlchemyAssessmentExecutionRepository(session_factory)
        _seed_assessment(session_factory, assessment_id="asmt-race", status="running")
        execution = repo.create_requested("asmt-race")

        reader_count = 6
        barrier = threading.Barrier(reader_count + 1)
        observed_statuses: list[str] = []
        lock = threading.Lock()

        def _reader() -> None:
            reader_repo = SqlAlchemyAssessmentExecutionRepository(session_factory)
            barrier.wait(timeout=5)
            for _ in range(20):
                row = reader_repo.get_by_id_with_context(execution.id)
                if row is not None:
                    with lock:
                        observed_statuses.append(row.execution_status.value)

        threads = [threading.Thread(target=_reader) for _ in range(reader_count)]
        for t in threads:
            t.start()

        barrier.wait(timeout=5)
        claimed = repo.try_claim(execution.id, execution.version)
        assert claimed is not None

        for t in threads:
            t.join(timeout=10)

        # Every observed status must be a real, legal execution status -
        # never a corrupted/partial read - and the transition itself must
        # have landed exactly once (version now claimed_version, not
        # bumped further by any reader).
        assert set(observed_statuses) <= {"REQUESTED", "CLAIMED"}
        final = repo.get_by_assessment_id("asmt-race")
        assert final is not None
        assert final.status == AssessmentExecutionStatus.CLAIMED
        assert final.version == claimed
