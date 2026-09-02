"""KSEC-94-03: reproduce the residual race Phase 93 explicitly flagged and
deferred - not the multi-instance claim race Phase 93 closed, but the
NEXT boundary in the same sequence:

    atomic schedule claim (Phase 93 - CLOSED, not re-tested here)
          |
    submit_scan() SUCCEEDS
          |
    schedule finalization (with_run_completed() + save()) FAILS
          |
    schedule remains due (next_run never advanced)
          |
    a LATER poll cycle claims it again (a fresh, legitimate claim -
    Phase 93's own mechanism working exactly as designed)
          |
    submit_scan() is called AGAIN for the same logical occurrence

This test proves the ScanJob-record-duplication property using real
schedule persistence (a real on-disk SQLite database, the real
SqlAlchemyScheduleRepository, the real InProcessScheduler) - the ONLY
test double is the job service, and that is deliberate, not a
shortcut: KSEC-94-01's investigation found that the REAL, production
JobServicePort implementation (PersistentJobService/JobModel) does not
even persist the `config` dict (which is where schedule_id travels) -
`job_to_domain()` hardcodes `config={}` on every read, discarding it
unconditionally on write. A double that DOES retain what it was called
with is therefore the only way to observe, from outside the
scheduler, which occurrence each submit_scan() call was for - which is
itself the central finding this test exists to make visible, not an
artificial test convenience.

No time.sleep() anywhere in this file; the finalization failure is
injected deterministically via a repository subclass, not timing.
"""

from __future__ import annotations

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
from kingsec.application.use_cases.schedule_dto import CreateScheduleRequest
from kingsec.domain.schedule import ScanSchedule
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


class _OccurrenceTrackingJobService(InMemoryJobService):
    """Records the schedule_id each submit_scan() call was made for, by
    reading it back out of `config` - the exact field the real
    PersistentJobService silently drops on persistence (KSEC-94-01).
    A real, working InMemoryJobService underneath (delegates for real),
    not a bare recorder."""

    def __init__(self) -> None:
        super().__init__()
        self.submissions_by_schedule_id: list[str] = []

    def submit_scan(self, target: str, config: dict | None = None) -> ScanJob:
        schedule_id = (config or {}).get("schedule_id", "")
        self.submissions_by_schedule_id.append(schedule_id)
        return super().submit_scan(target, config)


class _FinalizationFailsOnceRepo(SqlAlchemyScheduleRepository):
    """Wraps the real repository, injecting exactly one deterministic
    save() failure - simulating "submit_scan() succeeded, but the
    subsequent schedule-completion write failed" (e.g. a concurrent
    modification, a transient database error, or any other cause -
    KSEC-94-01 deliberately does not need to know WHY save() can fail,
    only that InProcessScheduler's own try/except already treats any
    save() exception identically). try_claim() is untouched - Phase 93's
    mechanism is not being re-tested here, only exercised as a
    precondition."""

    def __init__(self, session_factory) -> None:
        super().__init__(session_factory)
        self.save_failures_remaining = 0

    def save(self, schedule: ScanSchedule) -> None:
        if self.save_failures_remaining > 0:
            self.save_failures_remaining -= 1
            raise ScheduleConflictError("simulated finalization failure (KSEC-94-03)")
        super().save(schedule)


@pytest.fixture
def engine(tmp_path: Path):
    db_path = tmp_path / f"schedule-finalization-{uuid.uuid4().hex}.sqlite3"
    eng = create_engine(f"sqlite:///{db_path}", future=True, connect_args={"timeout": 30})
    Base.metadata.create_all(eng)
    return eng


@pytest.fixture
def session_factory(engine):
    return sessionmaker(bind=engine, expire_on_commit=False, future=True)


def _make_schedule(repo: SqlAlchemyScheduleRepository) -> str:
    create_uc = CreateSchedule(repo, _FakeAuditPublisher())
    result = create_uc.execute(
        CreateScheduleRequest(
            name="Nightly scan",
            owner_user_id="alice",
            target="10.0.0.77",
            cron_expression="0 2 * * *",
            schedule_type="cron",
        )
    )
    return result.schedule.id


class TestResidualFinalizationFailureRace:
    def test_submission_success_plus_finalization_failure_creates_a_duplicate_job_on_the_next_cycle(
        self, session_factory
    ) -> None:
        repo = _FinalizationFailsOnceRepo(session_factory)
        schedule_id = _make_schedule(repo)
        job_service = _OccurrenceTrackingJobService()
        scheduler = InProcessScheduler(repo, job_service, _FakeClock())

        # --- Cycle 1: submit_scan() succeeds, finalization fails ---
        repo.save_failures_remaining = 1
        scheduler._poll_due_schedules()

        assert job_service.submissions_by_schedule_id == [schedule_id], (
            "cycle 1 must have submitted exactly once, for this schedule"
        )
        after_cycle_1 = repo.find_by_id(schedule_id)
        assert after_cycle_1.next_run is None, (
            "finalization failed, so next_run must remain unadvanced - the schedule is still due"
        )
        assert after_cycle_1.is_due("2030-01-01T00:00:00+00:00") is True

        # --- Cycle 2: a later, legitimate poll cycle re-claims the SAME
        # still-due occurrence (Phase 93's claim mechanism working
        # exactly as designed - this is not a bug in try_claim()) ---
        scheduler._poll_due_schedules()

        assert job_service.submissions_by_schedule_id == [schedule_id, schedule_id], (
            "the same schedule_id was submitted twice for what a user would recognize as the "
            "same logical scheduled occurrence - two independent ScanJob records now exist for it"
        )
        after_cycle_2 = repo.find_by_id(schedule_id)
        assert after_cycle_2.next_run is not None, "cycle 2's finalization succeeded, advancing next_run normally"

    def test_a_second_recurrence_after_a_successful_cycle_is_a_legitimate_separate_occurrence(
        self, session_factory
    ) -> None:
        """KSEC-94-02: proves the flip side - once a cycle finalizes
        successfully and next_run genuinely advances, that new due
        window is a DIFFERENT, legitimate occurrence, not a duplicate -
        the fix this phase evaluates must never suppress this."""
        repo = SqlAlchemyScheduleRepository(session_factory)
        schedule_id = _make_schedule(repo)
        job_service = _OccurrenceTrackingJobService()
        scheduler = InProcessScheduler(repo, job_service, _FakeClock())

        scheduler._poll_due_schedules()  # occurrence 1: succeeds normally
        after_first = repo.find_by_id(schedule_id)
        assert after_first.next_run is not None

        # Force the schedule due again (simulating time passing to the
        # next legitimate cron firing) by directly relaxing next_run to
        # the past - a deterministic stand-in for "later," not a sleep.
        from dataclasses import replace

        past_due = replace(after_first, next_run="2000-01-01T00:00:00")
        repo.save(past_due)

        scheduler._poll_due_schedules()  # occurrence 2: a genuinely new, later firing

        assert job_service.submissions_by_schedule_id == [schedule_id, schedule_id]
        # Both submissions are legitimate here (two DIFFERENT next_run
        # values were fulfilled, occurrence 1 then occurrence 2) -
        # contrasted with the test above, where both submissions
        # fulfilled the SAME next_run value (None, never advanced).
        final = repo.find_by_id(schedule_id)
        assert final.next_run is not None
        assert final.next_run != "2000-01-01T00:00:00"
