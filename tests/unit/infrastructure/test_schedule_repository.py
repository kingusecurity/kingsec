"""Tests for the SQLAlchemy schedule repository - KSEC-85-02.

Every schedule mutation use case (pause/resume/update/enable/disable/
trigger) and the in-process scheduler followed the same pattern: read the
complete ScanSchedule, mutate a local copy, then blind full-record save()
with no concurrency check - a classic lost update. Two callers reading the
same row and saving concurrently would silently clobber one another with
no error and no trace.

SqlAlchemyScheduleRepository.save() now optimistic-locks the update path:
the write is scoped to ``WHERE id = ? AND version = ?`` and only succeeds
if nobody else has written first; otherwise it raises
ScheduleConflictError. These tests exercise the REAL repository against a
real on-disk SQLite database - the sequential tests through the actual
PauseSchedule use case, and the two genuine multi-threaded concurrency
tests (threading.Thread/threading.Barrier, never sequential calls) via an
explicit read/write-barrier choreography against save() itself (see
TestConcurrentSameFieldRace's docstring for why calling a use case's
execute() from bare threads does not reliably force the race) - matching
the established pattern in test_organization_repository.py (KSEC-84-01)
for the identical class of race.
"""

from __future__ import annotations

import dataclasses
import threading
import uuid
from pathlib import Path

import pytest
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

from kingsec.application.errors import ScheduleConflictError
from kingsec.application.ports.outbound.audit_publisher import AuditPublisher
from kingsec.application.use_cases.create_schedule import CreateSchedule
from kingsec.application.use_cases.pause_schedule import PauseSchedule
from kingsec.application.use_cases.schedule_dto import CreateScheduleRequest, PauseScheduleRequest
from kingsec.domain.audit import AuditEntry
from kingsec.domain.schedule import ScheduleStatus
from kingsec.infrastructure.persistence.models import Base
from kingsec.infrastructure.scheduler.sqlalchemy_schedule_repository import SqlAlchemyScheduleRepository


class _FakeAuditPublisher(AuditPublisher):
    def __init__(self) -> None:
        self.entries: list[AuditEntry] = []

    def record(self, entry: AuditEntry) -> None:
        self.entries.append(entry)


@pytest.fixture
def engine(tmp_path: Path):
    """A real on-disk SQLite database file - a single shared StaticPool
    in-memory connection would serialize all access through one Python
    object and could never demonstrate a real interleaved race; each
    thread here gets its own independent DBAPI connection, subject to
    SQLite's own file-level locking, matching
    test_organization_repository.py's identical fixture."""
    db_path = tmp_path / f"schedules-{uuid.uuid4().hex}.sqlite3"
    eng = create_engine(f"sqlite:///{db_path}", future=True, connect_args={"timeout": 30})
    Base.metadata.create_all(eng)
    return eng


@pytest.fixture
def session_factory(engine):
    return sessionmaker(bind=engine, expire_on_commit=False, future=True)


@pytest.fixture
def repo(session_factory) -> SqlAlchemyScheduleRepository:
    return SqlAlchemyScheduleRepository(session_factory)


def _make_schedule(repo: SqlAlchemyScheduleRepository, *, owner: str = "alice"):
    create_uc = CreateSchedule(repo, _FakeAuditPublisher())
    result = create_uc.execute(
        CreateScheduleRequest(
            name="Nightly scan",
            owner_user_id=owner,
            target="example.com",
            cron_expression="0 2 * * *",
            schedule_type="cron",
        )
    )
    return result.schedule.id


class TestVersioning:
    def test_new_schedule_starts_at_version_one(self, repo: SqlAlchemyScheduleRepository) -> None:
        schedule_id = _make_schedule(repo)
        assert repo.find_by_id(schedule_id).version == 1

    def test_successful_update_increments_version(self, repo: SqlAlchemyScheduleRepository) -> None:
        schedule_id = _make_schedule(repo)
        pause_uc = PauseSchedule(repo, _FakeAuditPublisher())

        pause_uc.execute(PauseScheduleRequest(schedule_id=schedule_id, requesting_user_id="alice"))

        assert repo.find_by_id(schedule_id).version == 2

    def test_save_with_a_stale_version_raises_conflict_and_does_not_overwrite(
        self, repo: SqlAlchemyScheduleRepository
    ) -> None:
        """Sequential (not threaded) proof that a stale version is rejected -
        the threaded tests below prove the same property under a genuine
        race; this isolates the mechanism itself."""
        schedule_id = _make_schedule(repo)
        stale = repo.find_by_id(schedule_id)

        pause_uc = PauseSchedule(repo, _FakeAuditPublisher())
        pause_uc.execute(PauseScheduleRequest(schedule_id=schedule_id, requesting_user_id="alice"))  # version -> 2

        # `stale` still carries version=1 - saving it must be rejected, not
        # silently applied over the version-2 row.
        with pytest.raises(ScheduleConflictError):
            repo.save(stale)

        current = repo.find_by_id(schedule_id)
        assert current.paused is True, "the winning (version-2) write was reverted by the rejected stale save"
        assert current.version == 2


class TestConcurrentSameFieldRace:
    """Scenario 1: Thread A reads v1, Thread B reads v1, A writes v2
    (succeeds), B then attempts to write with its stale v1 (must fail with
    ScheduleConflictError, no data loss, no corruption).

    Calling PauseSchedule.execute() from two bare threads is NOT enough on
    its own to force this: execute() reads and writes in one fast, atomic
    call, so without an explicit read/write choreography SQLite's own
    write-serialization means the second thread's internal read often
    happens AFTER the first thread's write has already committed - both
    then legitimately succeed against different versions, proving nothing
    about the race (confirmed empirically: two bare threads calling
    execute() both returned "ok" in a real run). A read barrier followed
    by a write barrier makes the interleaving the mandated scenario
    actually describes deterministic instead of incidental, while still
    exercising the real save() optimistic-lock path end to end."""

    def test_two_concurrent_pauses_from_the_same_read_one_wins_one_conflicts(
        self, session_factory
    ) -> None:
        repo = SqlAlchemyScheduleRepository(session_factory)
        schedule_id = _make_schedule(repo)

        read_barrier = threading.Barrier(2)
        results: list[str] = []
        errors: list[BaseException] = []
        lock = threading.Lock()

        def _read_then_pause() -> None:
            try:
                existing = repo.find_by_id(schedule_id)
                read_barrier.wait(timeout=5)  # both threads hold the SAME (version=1) read before either writes
                repo.save(dataclasses.replace(existing, paused=True, status=ScheduleStatus.PAUSED))
                with lock:
                    results.append("ok")
            except ScheduleConflictError:
                with lock:
                    results.append("conflict")
            except BaseException as exc:  # pragma: no cover - would fail the test below
                errors.append(exc)

        threads = [threading.Thread(target=_read_then_pause) for _ in range(2)]
        for t in threads:
            t.start()
        for t in threads:
            t.join(timeout=10)

        assert errors == [], f"unexpected exception under concurrency: {errors!r}"
        assert sorted(results) == ["conflict", "ok"], f"expected exactly one winner, one conflict: {results!r}"

        final = repo.find_by_id(schedule_id)
        assert final.paused is True
        assert final.version == 2, "exactly one successful write should have occurred, not zero or two"


class TestConcurrentDifferentFieldsRace:
    """Scenario 2: Thread A and Thread B both read the same version, then
    race to persist DIFFERENT kinds of changes (pause vs. cron_expression)
    - one succeeds, the other gets a conflict, and the loser's rejected
    write must never silently revert the winner's already-persisted
    change. Same read/write-barrier choreography as the same-field test
    above, for the same reason (see its docstring)."""

    def test_pause_and_cron_update_race_the_loser_never_reverts_the_winner(self, session_factory) -> None:
        repo = SqlAlchemyScheduleRepository(session_factory)
        schedule_id = _make_schedule(repo)

        read_barrier = threading.Barrier(2)
        results: dict[str, str] = {}
        lock = threading.Lock()

        def _read_then_pause() -> None:
            existing = repo.find_by_id(schedule_id)
            read_barrier.wait(timeout=5)
            try:
                repo.save(dataclasses.replace(existing, paused=True, status=ScheduleStatus.PAUSED))
                with lock:
                    results["pause"] = "ok"
            except ScheduleConflictError:
                with lock:
                    results["pause"] = "conflict"

        def _read_then_update_cron() -> None:
            existing = repo.find_by_id(schedule_id)
            read_barrier.wait(timeout=5)
            try:
                repo.save(dataclasses.replace(existing, cron_expression="0 3 * * *"))
                with lock:
                    results["update"] = "ok"
            except ScheduleConflictError:
                with lock:
                    results["update"] = "conflict"

        t_pause = threading.Thread(target=_read_then_pause)
        t_update = threading.Thread(target=_read_then_update_cron)
        t_pause.start()
        t_update.start()
        t_pause.join(timeout=10)
        t_update.join(timeout=10)

        assert set(results.values()) == {"ok", "conflict"}, f"expected exactly one winner: {results!r}"

        final = repo.find_by_id(schedule_id)
        assert final.version == 2, "exactly one write should have been applied"

        if results["pause"] == "ok":
            # The winning pause was built from the pre-race read, so it
            # carries the ORIGINAL cron_expression forward unchanged - the
            # loser's rejected update must not have touched it either.
            assert final.paused is True
            assert final.cron_expression == "0 2 * * *"
        else:
            # The winning cron update was built from the pre-race read, so
            # it carries the ORIGINAL paused=False forward unchanged - the
            # loser's rejected pause must not have touched it.
            assert final.paused is False
            assert final.cron_expression == "0 3 * * *"


class TestScheduleStatusPreservedOnLoad:
    def test_status_round_trips(self, repo: SqlAlchemyScheduleRepository) -> None:
        schedule_id = _make_schedule(repo)
        assert repo.find_by_id(schedule_id).status == ScheduleStatus.ACTIVE
