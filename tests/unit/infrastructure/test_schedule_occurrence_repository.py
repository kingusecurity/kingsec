"""KSEC-98-01: SqlAlchemyScheduleOccurrenceRepository - the database-enforced
exactly-once identity underneath SubmitScheduledAssessment.

Against a real on-disk SQLite database throughout. The security property
under test is that UNIQUE(schedule_id, occurrence_key) is the actual
concurrency arbiter, not an application-level check-then-insert - proven
both functionally (first claim succeeds, second returns the same row,
unique constraint enforced at the DB level) and under real concurrency
(N threads racing the same claim/lock step, exactly one winner - no
time.sleep() anywhere, threading.Barrier only).
"""

from __future__ import annotations

import threading
import uuid
from pathlib import Path

import pytest
from sqlalchemy import create_engine, select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import sessionmaker

from kingsec.application.schedule_occurrence import OccurrenceStatus
from kingsec.infrastructure.persistence.models import Base, ScheduleOccurrenceORM
from kingsec.infrastructure.persistence.repositories.schedule_occurrence import (
    SqlAlchemyScheduleOccurrenceRepository,
)


@pytest.fixture
def engine(tmp_path: Path):
    db_path = tmp_path / f"schedule-occurrence-{uuid.uuid4().hex}.sqlite3"
    eng = create_engine(f"sqlite:///{db_path}", future=True, connect_args={"timeout": 30})
    Base.metadata.create_all(eng)
    return eng


@pytest.fixture
def session_factory(engine):
    return sessionmaker(bind=engine, expire_on_commit=False, future=True)


@pytest.fixture
def repo(session_factory) -> SqlAlchemyScheduleOccurrenceRepository:
    return SqlAlchemyScheduleOccurrenceRepository(session_factory)


class TestTryClaim:
    def test_first_claim_creates_a_fresh_claimed_row(self, repo: SqlAlchemyScheduleOccurrenceRepository) -> None:
        occ = repo.try_claim("sched-1", "2026-09-05T04:00:00")
        assert occ.schedule_id == "sched-1"
        assert occ.occurrence_key == "2026-09-05T04:00:00"
        assert occ.status == OccurrenceStatus.CLAIMED
        assert occ.assessment_id is None
        assert occ.version == 1

    def test_second_claim_of_the_same_occurrence_returns_the_existing_row_unchanged(
        self, repo: SqlAlchemyScheduleOccurrenceRepository
    ) -> None:
        first = repo.try_claim("sched-1", "2026-09-05T04:00:00")
        second = repo.try_claim("sched-1", "2026-09-05T04:00:00")
        assert second.id == first.id
        assert second.version == first.version
        assert second.status == OccurrenceStatus.CLAIMED

    def test_a_different_occurrence_key_on_the_same_schedule_succeeds_independently(
        self, repo: SqlAlchemyScheduleOccurrenceRepository
    ) -> None:
        first = repo.try_claim("sched-1", "2026-09-05T04:00:00")
        second = repo.try_claim("sched-1", "2026-09-06T04:00:00")
        assert first.id != second.id

    def test_the_same_occurrence_key_on_a_different_schedule_succeeds_independently(
        self, repo: SqlAlchemyScheduleOccurrenceRepository
    ) -> None:
        first = repo.try_claim("sched-1", "2026-09-05T04:00:00")
        second = repo.try_claim("sched-2", "2026-09-05T04:00:00")
        assert first.id != second.id
        assert second.schedule_id == "sched-2"

    def test_unique_constraint_is_enforced_at_the_database_level_not_only_in_application_code(
        self, session_factory
    ) -> None:
        """The security property itself: a bare INSERT bypassing the
        repository's own ON CONFLICT DO NOTHING must still be rejected by
        the database - proving the constraint, not the repository's
        courtesy, is the real arbiter."""
        with session_factory() as session:
            session.add(
                ScheduleOccurrenceORM(
                    id="occ-a",
                    schedule_id="sched-1",
                    occurrence_key="2026-09-05T04:00:00",
                    status=OccurrenceStatus.CLAIMED.value,
                    assessment_id=None,
                    version=1,
                    claimed_at="2026-09-05T00:00:00",
                    updated_at="2026-09-05T00:00:00",
                )
            )
            session.commit()

            session.add(
                ScheduleOccurrenceORM(
                    id="occ-b",
                    schedule_id="sched-1",
                    occurrence_key="2026-09-05T04:00:00",
                    status=OccurrenceStatus.CLAIMED.value,
                    assessment_id=None,
                    version=1,
                    claimed_at="2026-09-05T00:00:01",
                    updated_at="2026-09-05T00:00:01",
                )
            )
            with pytest.raises(IntegrityError):
                session.commit()

    def test_n_concurrent_claim_attempts_produce_exactly_one_row(
        self, session_factory
    ) -> None:
        """Real concurrency, real database, no sleeps: N threads all
        attempt try_claim() for the identical (schedule_id, occurrence_key)
        at the same instant (gated by a Barrier), proving the DB - not
        timing - is what makes only one row ever exist."""
        attempt_count = 8
        barrier = threading.Barrier(attempt_count)
        results: list[str] = []
        lock = threading.Lock()

        def _attempt() -> None:
            repo = SqlAlchemyScheduleOccurrenceRepository(session_factory)
            barrier.wait(timeout=5)
            occ = repo.try_claim("sched-race", "2026-09-05T04:00:00")
            with lock:
                results.append(occ.id)

        threads = [threading.Thread(target=_attempt) for _ in range(attempt_count)]
        for t in threads:
            t.start()
        for t in threads:
            t.join(timeout=10)

        assert len(results) == attempt_count
        assert len(set(results)) == 1, "every concurrent claimant must observe the SAME single occurrence row"

        with session_factory() as session:
            rows = session.execute(
                select(ScheduleOccurrenceORM).where(ScheduleOccurrenceORM.schedule_id == "sched-race")
            ).scalars().all()
        assert len(rows) == 1


class TestBeginCreationAndMarkAssessmentCreated:
    def test_try_begin_creation_succeeds_from_a_fresh_claim(
        self, repo: SqlAlchemyScheduleOccurrenceRepository
    ) -> None:
        occ = repo.try_claim("sched-1", "2026-09-05T04:00:00")
        locked = repo.try_begin_creation(occ.id, occ.version)
        assert locked == occ.version + 1

    def test_try_begin_creation_fails_against_a_stale_version(
        self, repo: SqlAlchemyScheduleOccurrenceRepository
    ) -> None:
        occ = repo.try_claim("sched-1", "2026-09-05T04:00:00")
        repo.try_begin_creation(occ.id, occ.version)  # advances version
        stale_retry = repo.try_begin_creation(occ.id, occ.version)  # same stale version again
        assert stale_retry is None

    def test_mark_assessment_created_advances_status_and_stores_the_assessment_id(
        self, repo: SqlAlchemyScheduleOccurrenceRepository
    ) -> None:
        occ = repo.try_claim("sched-1", "2026-09-05T04:00:00")
        locked = repo.try_begin_creation(occ.id, occ.version)
        assert locked is not None
        ok = repo.mark_assessment_created(occ.id, locked, "asmt-123")
        assert ok is True

        refreshed = repo.try_claim("sched-1", "2026-09-05T04:00:00")  # re-fetch current state
        assert refreshed.status == OccurrenceStatus.ASSESSMENT_CREATED
        assert refreshed.assessment_id == "asmt-123"
        assert refreshed.version == locked + 1

    def test_n_concurrent_begin_creation_attempts_produce_exactly_one_winner(
        self, session_factory
    ) -> None:
        repo_seed = SqlAlchemyScheduleOccurrenceRepository(session_factory)
        occ = repo_seed.try_claim("sched-race-2", "2026-09-05T04:00:00")

        attempt_count = 8
        barrier = threading.Barrier(attempt_count)
        results: list[int | None] = []
        lock = threading.Lock()

        def _attempt() -> None:
            repo = SqlAlchemyScheduleOccurrenceRepository(session_factory)
            barrier.wait(timeout=5)
            locked = repo.try_begin_creation(occ.id, occ.version)
            with lock:
                results.append(locked)

        threads = [threading.Thread(target=_attempt) for _ in range(attempt_count)]
        for t in threads:
            t.start()
        for t in threads:
            t.join(timeout=10)

        winners = [r for r in results if r is not None]
        assert len(winners) == 1, (
            f"{len(winners)} concurrent callers won try_begin_creation() against the same version - "
            "expected exactly 1, meaning CreateAssessment would have been called more than once"
        )


class TestBeginSubmissionAndMarkSubmitted:
    def test_full_lifecycle_claimed_to_submitted(self, repo: SqlAlchemyScheduleOccurrenceRepository) -> None:
        occ = repo.try_claim("sched-1", "2026-09-05T04:00:00")
        v1 = repo.try_begin_creation(occ.id, occ.version)
        assert v1 is not None
        assert repo.mark_assessment_created(occ.id, v1, "asmt-123") is True

        after_create = repo.try_claim("sched-1", "2026-09-05T04:00:00")
        assert after_create.status == OccurrenceStatus.ASSESSMENT_CREATED

        v2 = repo.try_begin_submission(occ.id, after_create.version)
        assert v2 is not None
        assert repo.mark_submitted(occ.id, v2) is True

        final = repo.try_claim("sched-1", "2026-09-05T04:00:00")
        assert final.status == OccurrenceStatus.SUBMITTED
        assert final.assessment_id == "asmt-123"

    def test_try_begin_submission_fails_if_status_is_not_assessment_created(
        self, repo: SqlAlchemyScheduleOccurrenceRepository
    ) -> None:
        occ = repo.try_claim("sched-1", "2026-09-05T04:00:00")
        # Still CLAIMED - never went through try_begin_creation/mark_assessment_created.
        result = repo.try_begin_submission(occ.id, occ.version)
        assert result is None

    def test_n_concurrent_begin_submission_attempts_produce_exactly_one_winner(
        self, session_factory
    ) -> None:
        repo_seed = SqlAlchemyScheduleOccurrenceRepository(session_factory)
        occ = repo_seed.try_claim("sched-race-3", "2026-09-05T04:00:00")
        v1 = repo_seed.try_begin_creation(occ.id, occ.version)
        assert v1 is not None
        assert repo_seed.mark_assessment_created(occ.id, v1, "asmt-999") is True
        current = repo_seed.try_claim("sched-race-3", "2026-09-05T04:00:00")

        attempt_count = 8
        barrier = threading.Barrier(attempt_count)
        results: list[int | None] = []
        lock = threading.Lock()

        def _attempt() -> None:
            repo = SqlAlchemyScheduleOccurrenceRepository(session_factory)
            barrier.wait(timeout=5)
            locked = repo.try_begin_submission(occ.id, current.version)
            with lock:
                results.append(locked)

        threads = [threading.Thread(target=_attempt) for _ in range(attempt_count)]
        for t in threads:
            t.start()
        for t in threads:
            t.join(timeout=10)

        winners = [r for r in results if r is not None]
        assert len(winners) == 1, (
            f"{len(winners)} concurrent callers won try_begin_submission() against the same version - "
            "expected exactly 1, meaning SubmitAssessment would have been called more than once"
        )
