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
from kingsec.application.jobs import InMemoryJobService, ScanJob
from kingsec.application.ports.outbound.audit_publisher import AuditPublisher
from kingsec.application.ports.outbound.clock_port import ClockPort
from kingsec.application.use_cases.create_schedule import CreateSchedule
from kingsec.application.use_cases.pause_schedule import PauseSchedule
from kingsec.application.use_cases.schedule_dto import CreateScheduleRequest, PauseScheduleRequest
from kingsec.domain.audit import AuditEntry
from kingsec.domain.schedule import ScheduleStatus
from kingsec.infrastructure.persistence.models import Base
from kingsec.infrastructure.scheduler import in_process_scheduler as in_process_scheduler_module
from kingsec.infrastructure.scheduler.in_process_scheduler import InProcessScheduler
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


# ── KSEC-86-02: dedicated concurrency coverage for Enable/Disable/Trigger and
# the in-process scheduler tick. Phase 85 proved the repository-level
# optimistic-lock mechanism using Pause and Update; these prove every
# remaining caller correctly participates in that SAME mechanism (not a
# redesign) - each test drives the exact field-copy shape its real use case
# produces through repo.save() directly, using the same read/write-barrier
# choreography as TestConcurrentSameFieldRace above, for the identical
# reason documented there.


class TestConcurrentEnableRace:
    def test_two_concurrent_enables_from_the_same_read_one_wins_one_conflicts(self, session_factory) -> None:
        repo = SqlAlchemyScheduleRepository(session_factory)
        schedule_id = _make_schedule(repo)
        # Start disabled so "enable" is a real transition, not a no-op.
        disabled = repo.find_by_id(schedule_id)
        repo.save(dataclasses.replace(disabled, enabled=False, paused=False, status=ScheduleStatus.DISABLED))

        read_barrier = threading.Barrier(2)
        results: list[str] = []
        lock = threading.Lock()

        def _read_then_enable() -> None:
            existing = repo.find_by_id(schedule_id)
            read_barrier.wait(timeout=5)
            try:
                repo.save(dataclasses.replace(existing, enabled=True, paused=False, status=ScheduleStatus.ACTIVE))
                with lock:
                    results.append("ok")
            except ScheduleConflictError:
                with lock:
                    results.append("conflict")

        threads = [threading.Thread(target=_read_then_enable) for _ in range(2)]
        for t in threads:
            t.start()
        for t in threads:
            t.join(timeout=10)

        assert sorted(results) == ["conflict", "ok"], f"expected exactly one winner, one conflict: {results!r}"

        final = repo.find_by_id(schedule_id)
        assert final.enabled is True
        assert final.version == 3, "disable (1->2) then exactly one winning enable (2->3)"


class TestConcurrentDisableRace:
    def test_two_concurrent_disables_from_the_same_read_one_wins_one_conflicts(self, session_factory) -> None:
        repo = SqlAlchemyScheduleRepository(session_factory)
        schedule_id = _make_schedule(repo)  # created enabled=True already

        read_barrier = threading.Barrier(2)
        results: list[str] = []
        lock = threading.Lock()

        def _read_then_disable() -> None:
            existing = repo.find_by_id(schedule_id)
            read_barrier.wait(timeout=5)
            try:
                repo.save(dataclasses.replace(existing, enabled=False, paused=False, status=ScheduleStatus.DISABLED))
                with lock:
                    results.append("ok")
            except ScheduleConflictError:
                with lock:
                    results.append("conflict")

        threads = [threading.Thread(target=_read_then_disable) for _ in range(2)]
        for t in threads:
            t.start()
        for t in threads:
            t.join(timeout=10)

        assert sorted(results) == ["conflict", "ok"], f"expected exactly one winner, one conflict: {results!r}"

        final = repo.find_by_id(schedule_id)
        assert final.enabled is False
        assert final.version == 2


class TestConcurrentTriggerRace:
    """Trigger Now (with_run_completed()) racing an Update (cron_expression
    change) from the same version - one succeeds, the other conflicts, and
    the loser's rejected write must never revert the winner's change."""

    def test_trigger_and_update_race_the_loser_never_reverts_the_winner(self, session_factory) -> None:
        repo = SqlAlchemyScheduleRepository(session_factory)
        schedule_id = _make_schedule(repo)

        read_barrier = threading.Barrier(2)
        results: dict[str, str] = {}
        lock = threading.Lock()

        def _read_then_trigger() -> None:
            existing = repo.find_by_id(schedule_id)
            read_barrier.wait(timeout=5)
            triggered = existing.with_run_completed(next_run="2026-01-02T00:00:00", now="2026-01-01T00:00:00")
            try:
                repo.save(triggered)
                with lock:
                    results["trigger"] = "ok"
            except ScheduleConflictError:
                with lock:
                    results["trigger"] = "conflict"

        def _read_then_update_cron() -> None:
            existing = repo.find_by_id(schedule_id)
            read_barrier.wait(timeout=5)
            try:
                repo.save(dataclasses.replace(existing, cron_expression="0 4 * * *"))
                with lock:
                    results["update"] = "ok"
            except ScheduleConflictError:
                with lock:
                    results["update"] = "conflict"

        t_trigger = threading.Thread(target=_read_then_trigger)
        t_update = threading.Thread(target=_read_then_update_cron)
        t_trigger.start()
        t_update.start()
        t_trigger.join(timeout=10)
        t_update.join(timeout=10)

        assert set(results.values()) == {"ok", "conflict"}, f"expected exactly one winner: {results!r}"

        final = repo.find_by_id(schedule_id)
        assert final.version == 2, "exactly one write should have been applied"

        if results["trigger"] == "ok":
            assert final.last_run == "2026-01-01T00:00:00"
            assert final.cron_expression == "0 2 * * *", "the rejected update must not have touched cron_expression"
        else:
            assert final.last_run is None, "the rejected trigger must not have touched last_run"
            assert final.cron_expression == "0 4 * * *"


class _RecordingLogger:
    """A minimal stand-in for the structured logger used by
    in_process_scheduler.py - structlog's WriteLoggerFactory writes
    directly to a stream rather than routing through stdlib ``logging``,
    so pytest's ``caplog`` fixture cannot observe it; this records calls
    directly, matching the pattern already used for the identical problem
    in test_extended_adapter.py's TestAuditRequestBestEffort."""

    def __init__(self) -> None:
        self.exception_calls: list[tuple[str, dict]] = []

    def exception(self, msg: str, **kwargs: object) -> None:
        self.exception_calls.append((msg, kwargs))

    def warning(self, *_args: object, **_kwargs: object) -> None:
        return

    def info(self, *_args: object, **_kwargs: object) -> None:
        return


class TestSchedulerTickRace:
    """KSEC-86-02 / scheduler-specific requirement: in_process_scheduler.py's
    own tick (find_due() -> with_run_completed() -> save()) is a second,
    independent caller of the exact same lost-update-prone pattern the
    schedule use cases have - Phase 85 fixed the underlying save()
    mechanism but never exercised the scheduler itself. Proves a
    scheduler-triggered stale write cannot silently overwrite a newer,
    concurrently-applied schedule state, and that the conflict is logged
    (not silently swallowed) rather than turned into a silent success.

    The interleaving is forced deterministically (no sleeps): the
    scheduler's own find_due() has already returned its (pre-race) reads
    by the time _poll_due_schedules() calls job_service.submit_scan() for
    a given schedule - so making the CONCURRENT external mutation a side
    effect of submit_scan() guarantees it completes strictly between the
    scheduler's read and its own with_run_completed()+save() write, with
    no timing assumptions.
    """

    class _TriggeringJobService(InMemoryJobService):
        def __init__(self, repo: SqlAlchemyScheduleRepository, schedule_id: str) -> None:
            super().__init__()
            self._repo = repo
            self._schedule_id = schedule_id
            self.submitted = False

        def submit_scan(self, target: str, config: dict | None = None) -> ScanJob:
            # The competing external mutation fires exactly once (on the
            # first submit_scan() call in the batch, regardless of which
            # schedule triggered it) - another actor pauses the target
            # schedule while the scheduler is mid-tick, from the SAME
            # version the scheduler already read via find_due(). Guarded
            # so a second, unrelated due schedule in the same batch (see
            # test_scheduler_continues_processing_other_schedules_after_a_conflict)
            # does not retrigger it a second time.
            if not self.submitted:
                existing = self._repo.find_by_id(self._schedule_id)
                self._repo.save(dataclasses.replace(existing, paused=True, status=ScheduleStatus.PAUSED))
                self.submitted = True
            return super().submit_scan(target, config)

    class _FakeClock(ClockPort):
        def now(self) -> float:
            return 0.0

    def test_scheduler_tick_losing_a_race_does_not_overwrite_the_concurrent_change(
        self, session_factory, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        repo = SqlAlchemyScheduleRepository(session_factory)
        schedule_id = _make_schedule(repo)  # enabled=True, paused=False, next_run=None -> immediately due

        job_service = self._TriggeringJobService(repo, schedule_id)
        scheduler = InProcessScheduler(repo, job_service, self._FakeClock())

        recorder = _RecordingLogger()
        monkeypatch.setattr(in_process_scheduler_module, "_logger", recorder)

        scheduler._poll_due_schedules()

        assert job_service.submitted is True, "the scheduler must still submit the scan job before its own save() races"

        final = repo.find_by_id(schedule_id)
        # The concurrent pause (version 1 -> 2) must survive; the
        # scheduler's own stale with_run_completed() write (also computed
        # from version 1) must be rejected, not silently applied on top.
        assert final.paused is True, "the scheduler's stale write silently overwrote the concurrent pause"
        assert final.version == 2, "exactly one write (the concurrent pause) should have succeeded"
        assert final.last_run is None, "the scheduler's conflicting with_run_completed() write must not have been applied"

        # The conflict must be logged, not silently swallowed - the
        # existing `except Exception: _logger.exception(...)` boundary in
        # _poll_due_schedules() (Phase 84/85's established, deliberately
        # broad per-schedule catch, so one schedule's failure never stops
        # the rest of the batch from being processed).
        assert len(recorder.exception_calls) == 1
        msg, kwargs = recorder.exception_calls[0]
        assert msg == "failed to process due schedule"
        assert kwargs.get("schedule_id") == schedule_id

    def test_scheduler_continues_processing_other_schedules_after_a_conflict(
        self, session_factory, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """The conflict on one schedule must not abort the whole poll
        cycle - a second, unrelated due schedule in the same batch must
        still be processed successfully."""
        repo = SqlAlchemyScheduleRepository(session_factory)
        conflicting_id = _make_schedule(repo, owner="alice")

        create_uc = CreateSchedule(repo, _FakeAuditPublisher())
        other_id = create_uc.execute(
            CreateScheduleRequest(
                name="Other scan", owner_user_id="bob", target="other.example",
                cron_expression="0 3 * * *", schedule_type="cron",
            )
        ).schedule.id

        job_service = self._TriggeringJobService(repo, conflicting_id)
        scheduler = InProcessScheduler(repo, job_service, self._FakeClock())
        monkeypatch.setattr(in_process_scheduler_module, "_logger", _RecordingLogger())

        scheduler._poll_due_schedules()

        other_final = repo.find_by_id(other_id)
        assert other_final.last_run is not None, "an unrelated due schedule in the same batch must still be processed"
        assert other_final.version == 2


class TestDeleteRacingUpdate:
    """KSEC-87-03: delete_schedule() racing update/enable/disable/trigger.
    Both scenarios below force the SAME deterministic choreography as
    every other test in this file (read barrier, then an Event
    controlling which write commits first) - never sleeps, never
    incidental timing.

    Building Scenario A surfaced a genuine, previously-undiscovered bug:
    save()'s insert-vs-update branching decided "genuinely new schedule"
    purely from "no row exists at this id" - which is ALSO true the
    instant after a concurrent delete_schedule() removes a row that DID
    exist. A stale "update" attempt racing a delete would silently take
    the INSERT branch and resurrect the deleted schedule under its own
    stale field values - the exact "does not resurrect deleted state"
    failure Section 10's Additional Verification requires ruling out.
    save() originally (Phase 87) only took the insert branch when
    schedule.version == 1, since that was the only case it couldn't
    distinguish from a genuinely new id - any other version on a
    since-deleted row was correctly reported as a conflict. Phase 88
    (KSEC-88-03) closed that remaining version-1 gap structurally:
    delete() now tombstones the row (sets ``deleted_at``) instead of
    removing it, so save() can tell "never existed" apart from "existed
    and was deleted" with certainty, regardless of version - see
    TestVersionOneDeleteRace below for the case this specifically closes.
    """

    def test_scenario_a_delete_wins_stale_update_cannot_resurrect_or_modify(self, session_factory) -> None:
        """read schedule -> DELETE wins -> UPDATE attempts stale write.

        Uses a schedule already bumped to version 2 (via one prior
        pause) before the race, not a freshly-created version-1 schedule.
        The version-1 case (a schedule deleted before its first-ever
        update) is exercised separately below in
        TestVersionOneDeleteRace, since Phase 88's tombstone fix now
        closes it too - it's no longer a distinct code path here, but
        kept as its own test for the same reason this scenario is: proof
        specific to the exact case that was once a gap.
        """
        repo = SqlAlchemyScheduleRepository(session_factory)
        schedule_id = _make_schedule(repo)
        PauseSchedule(repo, _FakeAuditPublisher()).execute(
            PauseScheduleRequest(schedule_id=schedule_id, requesting_user_id="alice")
        )  # version 1 -> 2, so the race below starts from version 2

        read_barrier = threading.Barrier(2)
        delete_committed = threading.Event()
        results: dict[str, str] = {}
        lock = threading.Lock()

        def _delete() -> None:
            repo.find_by_id(schedule_id)  # "read schedule" per the scenario, even though delete() takes only an id
            read_barrier.wait(timeout=5)
            repo.delete(schedule_id)
            delete_committed.set()

        def _stale_update() -> None:
            existing = repo.find_by_id(schedule_id)
            read_barrier.wait(timeout=5)
            assert delete_committed.wait(timeout=5), "delete must commit before the stale update is attempted"
            try:
                repo.save(dataclasses.replace(existing, cron_expression="0 9 * * *"))
                with lock:
                    results["update"] = "ok"
            except ScheduleConflictError:
                with lock:
                    results["update"] = "conflict"

        t_delete = threading.Thread(target=_delete)
        t_update = threading.Thread(target=_stale_update)
        t_delete.start()
        t_update.start()
        t_delete.join(timeout=10)
        t_update.join(timeout=10)

        assert results["update"] == "conflict", (
            "a stale update racing a delete must be rejected, not silently swallowed or "
            "misreported as success"
        )
        assert repo.find_by_id(schedule_id) is None, (
            "the schedule must remain deleted - the stale update must not have resurrected it "
            "(this is the exact bug this test caught before the version != 1 fix)"
        )

    def test_scenario_b_update_wins_stale_delete_still_removes_the_updated_row(self, session_factory) -> None:
        """read schedule -> UPDATE wins -> DELETE attempts stale operation.

        Documents, rather than invents, the actual repository semantics:
        SqlAlchemyScheduleRepository.delete() (and DeleteScheduleRequest
        above it) takes only an id, never a version - it is
        authorization-gated (owner/admin, in delete_schedule.py) but NOT
        concurrency-gated. A "stale" delete is therefore not actually
        stale from delete()'s own point of view: it unconditionally
        removes whatever row currently exists at that id, including one
        a concurrent update just changed. This is the real, current
        behavior - not something this phase invents or fixes; flagged in
        the Phase 87 report as a documented asymmetry (updates are
        version-gated, deletes are not) for a future phase to weigh in on.
        """
        repo = SqlAlchemyScheduleRepository(session_factory)
        schedule_id = _make_schedule(repo)

        read_barrier = threading.Barrier(2)
        update_committed = threading.Event()

        def _update() -> None:
            existing = repo.find_by_id(schedule_id)
            read_barrier.wait(timeout=5)
            repo.save(dataclasses.replace(existing, cron_expression="0 9 * * *"))
            update_committed.set()

        def _stale_delete() -> None:
            repo.find_by_id(schedule_id)  # stale read, same pre-race version as _update's read
            read_barrier.wait(timeout=5)
            assert update_committed.wait(timeout=5), "update must commit before the stale delete is attempted"
            repo.delete(schedule_id)

        t_update = threading.Thread(target=_update)
        t_delete = threading.Thread(target=_stale_delete)
        t_update.start()
        t_delete.start()
        t_update.join(timeout=10)
        t_delete.join(timeout=10)

        # The documented actual semantics: the delete succeeds regardless
        # of the update that happened first - no error, no conflict,
        # because delete() never inspected a version at all.
        assert repo.find_by_id(schedule_id) is None, (
            "delete() is unconditional by id - it removes the row (now holding the winning "
            "update's content) even though it was 'stale' relative to that update"
        )


class TestVersionOneDeleteRace:
    """KSEC-88-03: the residual gap Phase 87 documented but did not close -
    a schedule deleted before its very first update (still at version 1)
    raced by a stale save() that also read it at version 1. Phase 87's
    `version != 1` heuristic could not detect this case at all, since a
    stale version-1 write racing the delete of a genuinely-version-1
    schedule was indistinguishable from a brand-new insert. The tombstone
    fix (delete() sets deleted_at instead of removing the row) closes
    this with certainty instead of inference: a stale save() now always
    finds the tombstoned row present, regardless of which version it read.
    """

    def test_delete_of_a_never_updated_schedule_cannot_be_resurrected_by_a_stale_save(
        self, session_factory
    ) -> None:
        """read (version 1) -> DELETE wins -> stale save(version=1)
        attempts to write. This is exactly the case Phase 87 could not
        protect: no prior update ever happened, so both the delete and
        the stale save race from a freshly-created, still-version-1 row."""
        repo = SqlAlchemyScheduleRepository(session_factory)
        schedule_id = _make_schedule(repo)  # created at version 1, never updated

        read_barrier = threading.Barrier(2)
        delete_committed = threading.Event()
        results: dict[str, str] = {}
        lock = threading.Lock()

        def _delete() -> None:
            repo.find_by_id(schedule_id)
            read_barrier.wait(timeout=5)
            repo.delete(schedule_id)
            delete_committed.set()

        def _stale_save() -> None:
            existing = repo.find_by_id(schedule_id)
            assert existing.version == 1, "this test only proves something if the race starts from version 1"
            read_barrier.wait(timeout=5)
            assert delete_committed.wait(timeout=5), "delete must commit before the stale save is attempted"
            try:
                repo.save(dataclasses.replace(existing, cron_expression="0 9 * * *"))
                with lock:
                    results["save"] = "ok"
            except ScheduleConflictError:
                with lock:
                    results["save"] = "conflict"

        t_delete = threading.Thread(target=_delete)
        t_save = threading.Thread(target=_stale_save)
        t_delete.start()
        t_save.start()
        t_delete.join(timeout=10)
        t_save.join(timeout=10)

        assert results["save"] == "conflict", (
            "a stale version-1 save racing the delete of that same version-1 schedule must be "
            "rejected - before the tombstone fix this silently succeeded and resurrected the "
            "deleted schedule as a 'new' insert"
        )
        assert repo.find_by_id(schedule_id) is None, "the schedule must remain deleted, not resurrected"

    def test_legitimate_create_of_a_genuinely_new_id_still_works(self, repo: SqlAlchemyScheduleRepository) -> None:
        """The tombstone check must not treat every version-1 save() as
        suspect - an id with no row at all (never created, never
        deleted) must still insert normally."""
        schedule_id = _make_schedule(repo)
        created = repo.find_by_id(schedule_id)
        assert created is not None
        assert created.version == 1

    def test_legitimate_update_of_a_live_schedule_still_works(self, repo: SqlAlchemyScheduleRepository) -> None:
        """A normal (non-racing) update against a live, non-tombstoned
        row must still succeed exactly as before."""
        schedule_id = _make_schedule(repo)
        existing = repo.find_by_id(schedule_id)
        repo.save(dataclasses.replace(existing, cron_expression="0 5 * * *"))

        updated = repo.find_by_id(schedule_id)
        assert updated.cron_expression == "0 5 * * *"
        assert updated.version == 2

    def test_failed_stale_save_does_not_partially_mutate_the_tombstoned_row(self, session_factory) -> None:
        """The rejected stale save() must leave the tombstoned row exactly
        as delete() left it - no field from the stale write leaking
        through, no version bump, no un-tombstoning."""
        repo = SqlAlchemyScheduleRepository(session_factory)
        schedule_id = _make_schedule(repo)
        existing = repo.find_by_id(schedule_id)
        repo.delete(schedule_id)

        with pytest.raises(ScheduleConflictError):
            repo.save(dataclasses.replace(existing, cron_expression="0 9 * * *", name="mutated"))

        assert repo.find_by_id(schedule_id) is None, "still tombstoned/invisible - the stale write did not un-delete it"

        # Inspect the raw row directly (find_by_id() filters tombstoned
        # rows out by design) to prove the stale write's fields never
        # reached storage at all, not merely that the row stays hidden.
        from sqlalchemy import select

        from kingsec.infrastructure.persistence.models import ScheduleORM

        with session_factory() as session:
            raw = session.execute(select(ScheduleORM).where(ScheduleORM.id == str(schedule_id))).scalar_one()
        assert raw.deleted_at is not None
        assert raw.cron_expression == "0 2 * * *", "the stale save's cron_expression must not have been written"
        assert raw.name == "Nightly scan", "the stale save's name must not have been written"
        assert raw.version == 1, "the rejected save must not have incremented the version"
