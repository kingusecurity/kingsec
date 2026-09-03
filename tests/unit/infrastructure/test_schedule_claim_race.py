"""KSEC-93: scheduler duplicate-execution / atomic due-schedule claiming.

Phase 92 documented, but explicitly did not fix, a confirmed multi-instance
duplicate-execution risk: InProcessScheduler's own poll cycle called
job_service.submit_scan() BEFORE the schedule's optimistic-locked version
check (in with_run_completed()+save()), so two scheduler instances sharing
one database could both see the same due schedule via find_due() and both
call submit_scan() before either one's state write ever happened - the
version check only decided which write "won," not which submission
happened, and by then both had already happened.

Phase 93 closes this by adding ScheduleRepositoryPort.try_claim() - a
single atomic conditional UPDATE (the same idiom as save()'s own
optimistic lock and Phase 87's AssessmentConcurrencyPort.try_reserve_slot())
that InProcessScheduler now calls BEFORE submit_scan(), not after. These
tests prove the actual security property this phase exists to establish:

    SAME DUE SCHEDULE + TWO SCHEDULER INSTANCES -> EXACTLY ONE ATOMIC CLAIM
    -> EXACTLY ONE submit_scan()

against a real on-disk SQLite database, real SqlAlchemyScheduleRepository
instances, and real InProcessScheduler instances - never a single scheduler
object raced against itself, never the repository method tested in
isolation from the actual scheduler claim/execution boundary. All
synchronization uses threading.Barrier/threading.Event; no time.sleep()
anywhere in this file.
"""

from __future__ import annotations

import threading
import uuid
from pathlib import Path

import pytest
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

from kingsec.application.errors import ScheduleConflictError
from kingsec.application.ports.outbound.audit_publisher import AuditPublisher
from kingsec.application.ports.outbound.clock_port import ClockPort
from kingsec.application.use_cases.create_schedule import CreateSchedule
from kingsec.application.use_cases.pause_schedule import PauseSchedule
from kingsec.application.use_cases.schedule_dto import CreateScheduleRequest, PauseScheduleRequest
from kingsec.infrastructure.persistence.models import Base
from kingsec.infrastructure.scheduler.in_process_scheduler import InProcessScheduler
from kingsec.infrastructure.scheduler.sqlalchemy_schedule_repository import SqlAlchemyScheduleRepository


class _FakeAuditPublisher(AuditPublisher):
    def __init__(self) -> None:
        self.entries: list = []

    def record(self, entry) -> None:
        self.entries.append(entry)


class _FakeClock(ClockPort):
    def now(self) -> float:
        return 0.0


class _RecordingOrchestrator:
    """KSEC-98-01: stands in for SubmitScheduledAssessment - counts calls
    and records targets, the deterministic boundary these tests need to
    prove "exactly one winner submitted," matching the established
    _TriggeringOrchestrator pattern in test_schedule_repository.py. This
    test's subject is the schedule-level claim race, not scheduled-
    assessment orchestration, so a minimal fake with the same
    execute(schedule) shape is sufficient."""

    def __init__(self) -> None:
        self.call_count = 0
        self.submitted_targets: list[str] = []

    def execute(self, schedule: object) -> None:
        self.call_count += 1
        self.submitted_targets.append(schedule.target)


class _BarrierGatedRepo(SqlAlchemyScheduleRepository):
    """Wraps the real repository, waiting on a shared Barrier immediately
    after find_due() returns its real result and before the caller can
    act on it - forcing two independent scheduler threads to both hold
    the SAME stale read before either one's try_claim() runs, exactly
    mirroring test_schedule_repository.py's own established "barrier
    right after the read" choreography for the identical class of race."""

    def __init__(self, session_factory, barrier: threading.Barrier) -> None:
        super().__init__(session_factory)
        self._barrier = barrier

    def find_due(self, now_utc_str: str):
        result = super().find_due(now_utc_str)
        self._barrier.wait(timeout=5)
        return result


@pytest.fixture
def engine(tmp_path: Path):
    db_path = tmp_path / f"schedule-claim-{uuid.uuid4().hex}.sqlite3"
    eng = create_engine(f"sqlite:///{db_path}", future=True, connect_args={"timeout": 30})
    Base.metadata.create_all(eng)
    return eng


@pytest.fixture
def session_factory(engine):
    return sessionmaker(bind=engine, expire_on_commit=False, future=True)


@pytest.fixture
def repo(session_factory) -> SqlAlchemyScheduleRepository:
    return SqlAlchemyScheduleRepository(session_factory)


def _make_schedule(repo: SqlAlchemyScheduleRepository, *, owner: str = "alice") -> str:
    create_uc = CreateSchedule(repo, _FakeAuditPublisher())
    result = create_uc.execute(
        CreateScheduleRequest(
            name="Nightly scan",
            owner_user_id=owner,
            target="10.0.0.50",
            cron_expression="0 2 * * *",
            schedule_type="cron",
        )
    )
    return result.schedule.id


class TestTryClaimBasicSemantics:
    """KSEC-93-13 items 1, 2, 9, 10, 11: the non-concurrent claim
    contract, proven sequentially first - the race tests below prove the
    same contract holds under genuine concurrency."""

    def test_first_claimant_succeeds(self, repo: SqlAlchemyScheduleRepository) -> None:
        schedule_id = _make_schedule(repo)
        schedule = repo.find_by_id(schedule_id)
        claimed = repo.try_claim(schedule)
        assert claimed is not None
        assert claimed.version == schedule.version + 1

    def test_second_claimant_with_the_same_stale_version_loses(self, repo: SqlAlchemyScheduleRepository) -> None:
        schedule_id = _make_schedule(repo)
        schedule = repo.find_by_id(schedule_id)
        first = repo.try_claim(schedule)
        assert first is not None
        second = repo.try_claim(schedule)  # same stale (pre-claim) version as `first` started from
        assert second is None, "a second claim attempt from the same stale version must lose"

    def test_normal_due_schedule_can_be_claimed(self, repo: SqlAlchemyScheduleRepository) -> None:
        schedule_id = _make_schedule(repo)
        schedule = repo.find_by_id(schedule_id)
        assert schedule.is_due("2030-01-01T00:00:00+00:00") is True
        assert repo.try_claim(schedule) is not None

    def test_tombstoned_schedule_cannot_be_claimed(self, repo: SqlAlchemyScheduleRepository) -> None:
        schedule_id = _make_schedule(repo)
        schedule = repo.find_by_id(schedule_id)
        repo.delete(schedule_id)
        assert repo.try_claim(schedule) is None, "a claim against a since-tombstoned schedule must fail"

    def test_paused_schedule_cannot_be_claimed_even_with_a_matching_version(
        self, repo: SqlAlchemyScheduleRepository
    ) -> None:
        """A schedule can be read (e.g. by a stale find_due() result that
        predates a pause) and then paused before the claim attempt - the
        claim's own WHERE clause must re-check `paused` at claim time,
        not only trust the version number, since a pause is itself a
        version-bumping write that a subsequent read would already see."""
        schedule_id = _make_schedule(repo)
        pre_pause = repo.find_by_id(schedule_id)
        PauseSchedule(repo, _FakeAuditPublisher()).execute(
            PauseScheduleRequest(schedule_id=schedule_id, requesting_user_id="alice")
        )
        post_pause = repo.find_by_id(schedule_id)
        assert post_pause.paused is True
        # Claiming with the CURRENT (post-pause) version must still fail,
        # because the schedule is paused - version match alone is not
        # sufficient for a valid claim.
        assert repo.try_claim(post_pause) is None
        # And the original, now-stale pre-pause version was already
        # doomed by the version check alone, independent of the pause.
        assert repo.try_claim(pre_pause) is None

    def test_claim_release_and_finalization_completes_the_normal_flow(
        self, repo: SqlAlchemyScheduleRepository
    ) -> None:
        """KSEC-93-13 item 6: there is no separate "release" call in this
        design (see the Phase 93 report for why a lease/release
        mechanism is unnecessary) - "finalization" is simply that the
        caller can still successfully complete the normal
        with_run_completed()+save() write using the claimed copy."""
        schedule_id = _make_schedule(repo)
        schedule = repo.find_by_id(schedule_id)
        claimed = repo.try_claim(schedule)
        assert claimed is not None
        finalized = claimed.with_run_completed(next_run="2030-01-02T00:00:00", now="2030-01-01T00:00:00")
        repo.save(finalized)  # must not raise
        stored = repo.find_by_id(schedule_id)
        assert stored.version == claimed.version + 1
        assert stored.last_run == "2030-01-01T00:00:00"

    def test_failed_submission_does_not_permanently_strand_the_schedule(
        self, repo: SqlAlchemyScheduleRepository
    ) -> None:
        """KSEC-93-13 item 7: if submit_scan() fails after a successful
        claim, with_run_completed() is never called (next_run stays
        unchanged), so the schedule remains due and is claimable again
        on the next poll cycle - proven directly, not merely asserted:
        claim, simulate the failure by doing nothing further (no
        with_run_completed()/save()), then claim again from the new
        current version and confirm it succeeds and the schedule is
        still recognized as due."""
        schedule_id = _make_schedule(repo)
        schedule = repo.find_by_id(schedule_id)
        first_claim = repo.try_claim(schedule)
        assert first_claim is not None
        # Simulated failure: submit_scan() raised, so nothing calls
        # with_run_completed()/save() - next_run is still None (always due).
        still_due = repo.find_by_id(schedule_id)
        assert still_due.is_due("2030-01-01T00:00:00+00:00") is True
        second_claim = repo.try_claim(still_due)
        assert second_claim is not None, "a schedule must remain claimable after a prior claim's submission failed"


class TestConcurrentClaimRace:
    """KSEC-93-07: the core mandatory race test - two independent claim
    attempts against the real repository, forced to race deterministically."""

    @pytest.mark.parametrize("run", range(5))
    def test_exactly_one_of_many_concurrent_claimants_wins(self, run: int, session_factory) -> None:
        repo_seed = SqlAlchemyScheduleRepository(session_factory)
        schedule_id = _make_schedule(repo_seed)
        schedule = repo_seed.find_by_id(schedule_id)

        attempt_count = 10
        start = threading.Barrier(attempt_count)
        results: list[bool] = []
        lock = threading.Lock()

        def _attempt() -> None:
            repo = SqlAlchemyScheduleRepository(session_factory)
            start.wait(timeout=5)  # every thread races to claim from the SAME stale read
            claimed = repo.try_claim(schedule)
            with lock:
                results.append(claimed is not None)

        threads = [threading.Thread(target=_attempt) for _ in range(attempt_count)]
        for t in threads:
            t.start()
        for t in threads:
            t.join(timeout=10)

        winners = sum(1 for r in results if r)
        assert len(results) == attempt_count
        assert winners == 1, (
            f"run {run}: {winners} concurrent claimants won against the same version - "
            "expected exactly 1, meaning the atomic conditional UPDATE let more than one succeed"
        )
        final = repo_seed.find_by_id(schedule_id)
        assert final.version == schedule.version + 1


class TestConcurrentSchedulerInstanceRace:
    """KSEC-93-08: the mandatory multi-instance test - two REAL,
    independent InProcessScheduler objects (never one object raced
    against itself), each with its OWN repository instance (simulating
    two separate processes/containers), against the same real on-disk
    SQLite database and the same real, persisted due schedule."""

    @pytest.mark.parametrize("run", range(5))
    def test_two_scheduler_instances_racing_the_same_due_schedule_produce_exactly_one_submission(
        self, run: int, session_factory
    ) -> None:
        seed_repo = SqlAlchemyScheduleRepository(session_factory)
        schedule_id = _make_schedule(seed_repo)

        barrier = threading.Barrier(2)
        repo_a = _BarrierGatedRepo(session_factory, barrier)
        repo_b = _BarrierGatedRepo(session_factory, barrier)

        job_service_a = _RecordingOrchestrator()
        job_service_b = _RecordingOrchestrator()
        scheduler_a = InProcessScheduler(repo_a, job_service_a, _FakeClock())
        scheduler_b = InProcessScheduler(repo_b, job_service_b, _FakeClock())

        thread_a = threading.Thread(target=scheduler_a._poll_due_schedules)
        thread_b = threading.Thread(target=scheduler_b._poll_due_schedules)
        thread_a.start()
        thread_b.start()
        thread_a.join(timeout=10)
        thread_b.join(timeout=10)

        total_submissions = job_service_a.call_count + job_service_b.call_count
        assert total_submissions == 1, (
            f"run {run}: {total_submissions} scheduler instances submitted the same due schedule - "
            "expected exactly 1; the losing instance must never reach submit_scan()"
        )
        # Exactly one of the two instances is the winner; the other made
        # zero submissions - not "both tried and one failed midway."
        assert {job_service_a.call_count, job_service_b.call_count} == {0, 1}

        final = seed_repo.find_by_id(schedule_id)
        assert final is not None
        assert final.next_run is not None, "the winning instance's with_run_completed() write must have advanced next_run"
        assert final.version == 3, "claim (v1->v2) + the winner's own with_run_completed() write (v2->v3)"


class TestVersionAndTombstoneSemanticsPreserved:
    """KSEC-93-10: confirm the claim mechanism does not alter version or
    tombstone semantics for callers that never claim at all - the
    ordinary create/update/delete paths must be entirely unaffected."""

    def test_ordinary_save_without_claiming_is_unaffected(self, repo: SqlAlchemyScheduleRepository) -> None:
        schedule_id = _make_schedule(repo)
        schedule = repo.find_by_id(schedule_id)
        assert schedule.version == 1
        PauseSchedule(repo, _FakeAuditPublisher()).execute(
            PauseScheduleRequest(schedule_id=schedule_id, requesting_user_id="alice")
        )
        updated = repo.find_by_id(schedule_id)
        assert updated.version == 2, "a normal update must still bump the version by exactly one, unaffected by try_claim()"

    def test_stale_save_after_a_claim_is_still_rejected_as_a_conflict(
        self, repo: SqlAlchemyScheduleRepository
    ) -> None:
        schedule_id = _make_schedule(repo)
        stale = repo.find_by_id(schedule_id)
        repo.try_claim(stale)  # bumps v1->v2 underneath the stale reader
        with pytest.raises(ScheduleConflictError):
            repo.save(stale.with_run_completed(next_run=None, now="2030-01-01T00:00:00"))
