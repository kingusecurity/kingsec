"""Tests for the SQLAlchemy assessment concurrency-slot repository -
KSEC-87-02.

`max_concurrent_assessments` existed as configuration but was never
enforced - a naive "count running, then start if under the limit" check
is unsafe (two concurrent requests could both observe capacity and both
start, recreating the exact TOCTOU class Phases 85/86 closed for
schedules/organizations/teams). SqlAlchemyAssessmentConcurrencyRepository
closes this with a single atomic conditional UPDATE per reserve/release -
no separate read-then-write step exists in application code for a
concurrent caller to race.

These tests exercise the REAL repository against a real on-disk SQLite
database, including a genuine multi-threaded race test (never sequential
calls), matching the established pattern in test_schedule_repository.py
(KSEC-85-02) and test_organization_repository.py (KSEC-84-01/86-01) for
the identical class of concurrency proof.
"""

from __future__ import annotations

import threading
import uuid
from pathlib import Path

import pytest
from sqlalchemy import create_engine, insert
from sqlalchemy.orm import sessionmaker

from kingsec.infrastructure.persistence.models import AssessmentConcurrencySlotORM, Base
from kingsec.infrastructure.persistence.repositories.assessment_concurrency import (
    SqlAlchemyAssessmentConcurrencyRepository,
)


@pytest.fixture
def engine(tmp_path: Path):
    """A real on-disk SQLite database file - a single shared in-memory
    connection would serialize all access through one Python object and
    could never demonstrate a real interleaved race; each thread here
    gets its own independent DBAPI connection, subject to SQLite's own
    file-level write locking, matching test_schedule_repository.py's
    identical fixture."""
    db_path = tmp_path / f"assessment-concurrency-{uuid.uuid4().hex}.sqlite3"
    eng = create_engine(f"sqlite:///{db_path}", future=True, connect_args={"timeout": 30})
    Base.metadata.create_all(eng)
    # Seed the single row (id=1, active_count=0) - in production this is
    # done by the creating Alembic migration's own INSERT; Base.metadata.
    # create_all() only creates the empty table.
    with eng.begin() as conn:
        conn.execute(insert(AssessmentConcurrencySlotORM).values(id=1, active_count=0))
    return eng


@pytest.fixture
def session_factory(engine):
    return sessionmaker(bind=engine, expire_on_commit=False, future=True)


@pytest.fixture
def repo(session_factory) -> SqlAlchemyAssessmentConcurrencyRepository:
    return SqlAlchemyAssessmentConcurrencyRepository(session_factory)


def _active_count(session_factory) -> int:
    with session_factory() as session:
        row = session.get(AssessmentConcurrencySlotORM, 1)
        return row.active_count


class TestCapacityBelowLimit:
    def test_two_reservations_within_a_limit_of_two_both_succeed(
        self, repo: SqlAlchemyAssessmentConcurrencyRepository, session_factory
    ) -> None:
        assert repo.try_reserve_slot(2) is True
        assert repo.try_reserve_slot(2) is True
        assert _active_count(session_factory) == 2


class TestCapacityExhausted:
    def test_a_third_reservation_beyond_the_limit_is_rejected(
        self, repo: SqlAlchemyAssessmentConcurrencyRepository, session_factory
    ) -> None:
        assert repo.try_reserve_slot(2) is True
        assert repo.try_reserve_slot(2) is True
        assert repo.try_reserve_slot(2) is False, "capacity is already at the configured maximum"
        assert _active_count(session_factory) == 2, "the rejected attempt must not have incremented the counter"


class TestSlotRelease:
    def test_release_frees_capacity_for_a_subsequent_reservation(
        self, repo: SqlAlchemyAssessmentConcurrencyRepository, session_factory
    ) -> None:
        assert repo.try_reserve_slot(1) is True
        assert repo.try_reserve_slot(1) is False

        repo.release_slot()
        assert _active_count(session_factory) == 0

        assert repo.try_reserve_slot(1) is True, "a released slot must be claimable again"

    def test_release_below_zero_is_a_safe_no_op(
        self, repo: SqlAlchemyAssessmentConcurrencyRepository, session_factory
    ) -> None:
        """Defensive floor: a stray/duplicate release call (a bug, not
        the expected one-release-per-successful-reserve contract) must
        never drive the counter negative and corrupt capacity for every
        future caller."""
        repo.release_slot()
        repo.release_slot()
        assert _active_count(session_factory) == 0
        assert repo.try_reserve_slot(1) is True, "capacity must still be exactly 1, not corrupted negative"


class TestConcurrentReservationRace:
    """The core requirement (Section 9's "Race test"): start multiple
    concurrent reservation attempts simultaneously and prove successful
    reservations never exceed the configured maximum - repeated 5
    consecutive times to rule out a one-off timing coincidence, per the
    phase's explicit instruction."""

    @pytest.mark.parametrize("run", range(5))
    def test_successful_reservations_never_exceed_the_configured_maximum(
        self, run: int, session_factory
    ) -> None:
        repo = SqlAlchemyAssessmentConcurrencyRepository(session_factory)
        max_concurrent = 3
        attempt_count = 10  # more attempts than capacity, to force real contention

        results: list[bool] = []
        lock = threading.Lock()
        start = threading.Barrier(attempt_count)

        def _attempt() -> None:
            start.wait(timeout=5)  # all threads race to reserve at (as close to) the same instant
            reserved = repo.try_reserve_slot(max_concurrent)
            with lock:
                results.append(reserved)

        threads = [threading.Thread(target=_attempt) for _ in range(attempt_count)]
        for t in threads:
            t.start()
        for t in threads:
            t.join(timeout=10)

        successful = sum(1 for r in results if r)
        assert len(results) == attempt_count, "every thread must have completed its attempt"
        assert successful <= max_concurrent, (
            f"run {run}: {successful} reservations succeeded, exceeding the configured "
            f"maximum of {max_concurrent} - this would mean the atomic UPDATE let two "
            f"concurrent callers both observe capacity and both claim it"
        )
        assert successful == max_concurrent, (
            "exactly max_concurrent reservations should succeed (capacity was available "
            "and never released mid-race)"
        )
        assert _active_count(session_factory) == successful, (
            "the persisted counter must exactly match the number of successful reservations"
        )


class TestUnseededTable:
    """Regression test: database.py's ``create_schema()`` (used by test
    fixtures and documented as the non-production "quick-start" fallback,
    never ``alembic upgrade head``) only runs ``Base.metadata.create_all()``
    - it does NOT run the creating migration's own seed INSERT. Before the
    self-healing ``INSERT ... ON CONFLICT DO NOTHING`` in try_reserve_slot(),
    a table created this way had no id=1 row at all, so the conditional
    UPDATE matched zero rows on every call and every assessment start
    permanently failed with TooManyConcurrentAssessmentsError - regardless
    of the configured limit. This is exactly what
    tests/integration/bootstrap/test_composition.py's
    ``test_full_flow_through_wired_graph`` hit, since it wires the real
    composition root against a schema created via ``create_schema()``."""

    @pytest.fixture
    def unseeded_session_factory(self, tmp_path: Path):
        db_path = tmp_path / f"assessment-concurrency-unseeded-{uuid.uuid4().hex}.sqlite3"
        eng = create_engine(f"sqlite:///{db_path}", future=True, connect_args={"timeout": 30})
        Base.metadata.create_all(eng)  # deliberately no seed INSERT here
        return sessionmaker(bind=eng, expire_on_commit=False, future=True)

    def test_reservation_self_heals_a_table_created_without_the_seed_row(
        self, unseeded_session_factory
    ) -> None:
        repo = SqlAlchemyAssessmentConcurrencyRepository(unseeded_session_factory)
        assert repo.try_reserve_slot(5) is True, (
            "the row must be created on demand rather than every reservation "
            "permanently failing against a nonexistent counter row"
        )
        assert _active_count(unseeded_session_factory) == 1

    def test_a_second_self_healing_attempt_does_not_double_insert_or_error(
        self, unseeded_session_factory
    ) -> None:
        """Two callers racing the very first reservation against an
        unseeded table must not raise a unique-constraint error from a
        duplicate INSERT, and must not silently create two rows."""
        repo = SqlAlchemyAssessmentConcurrencyRepository(unseeded_session_factory)
        assert repo.try_reserve_slot(1) is True
        assert repo.try_reserve_slot(1) is False, "capacity of 1 is already claimed"
        assert _active_count(unseeded_session_factory) == 1


class TestConcurrentReservationAndReleaseInterleaving:
    """A second race shape: reservations and a release happening at the
    same time - proves release_slot() is equally safe under concurrency,
    not just try_reserve_slot() in isolation."""

    def test_a_release_racing_new_reservation_attempts_never_over_commits(self, session_factory) -> None:
        repo = SqlAlchemyAssessmentConcurrencyRepository(session_factory)
        max_concurrent = 2
        assert repo.try_reserve_slot(max_concurrent) is True
        assert repo.try_reserve_slot(max_concurrent) is True  # at capacity

        results: list[bool] = []
        lock = threading.Lock()
        start = threading.Barrier(3)  # 1 release + 2 competing new reservations

        def _release() -> None:
            start.wait(timeout=5)
            repo.release_slot()

        def _attempt() -> None:
            start.wait(timeout=5)
            reserved = repo.try_reserve_slot(max_concurrent)
            with lock:
                results.append(reserved)

        threads = [
            threading.Thread(target=_release),
            threading.Thread(target=_attempt),
            threading.Thread(target=_attempt),
        ]
        for t in threads:
            t.start()
        for t in threads:
            t.join(timeout=10)

        successful = sum(1 for r in results if r)
        # The release frees exactly one slot - at most one of the two
        # competing reservation attempts can win it.
        assert successful <= 1, f"{successful} reservations succeeded after only one slot was released"
        assert _active_count(session_factory) <= max_concurrent, "the counter must never exceed the configured cap"
