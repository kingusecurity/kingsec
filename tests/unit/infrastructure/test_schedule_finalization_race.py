"""KSEC-94-03 / KSEC-98-01: the residual finalization-failure race Phase 94
found and Phase 96/97 decided how to close - now proven fixed.

    atomic schedule claim (Phase 93 - CLOSED, not re-tested here)
          |
    SubmitScheduledAssessment.execute() SUCCEEDS (real assessment created
    and submitted, real occurrence marked SUBMITTED)
          |
    schedule finalization (with_run_completed() + save()) FAILS
          |
    schedule remains due (next_run never advanced)
          |
    a LATER poll cycle claims it again (a fresh, legitimate claim -
    Phase 93's own mechanism working exactly as designed)
          |
    InProcessScheduler calls the orchestrator AGAIN for the same schedule

Phase 94 proved this produced a second, independent ScanJob record via the
(inert) legacy pipeline. This file proves the NEW pipeline does not repeat
that mistake: the second call finds the occurrence already SUBMITTED
(KSEC-98-01's database-unique occurrence identity) and takes no further
action - exactly ONE real Assessment ever exists for the occurrence,
regardless of how many times the schedule-level retry fires.

Real schedule persistence throughout (a real on-disk SQLite database, the
real SqlAlchemyScheduleRepository, the real SqlAlchemyScheduleOccurrenceRepository,
the real InProcessScheduler, the real CreateAssessment/SubmitAssessment/
SubmitScheduledAssessment). Only ScannerPort/JobRunner are fakes (the same
FakeScanner/RecordingJobRunner already established in
tests/unit/application/test_submit_assessment.py) - a unit test has no
business actually invoking scanner binaries, and RecordingJobRunner's
run_inline=True makes the background submission synchronous and
deterministic, no threads or sleeps required.

No time.sleep() anywhere in this file; the finalization failure is
injected deterministically via a repository subclass, not timing.
"""

from __future__ import annotations

import uuid
from dataclasses import replace
from pathlib import Path
from typing import Any

import pytest
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

from kingsec.application.errors import AssessmentNotFoundError, ScheduleConflictError
from kingsec.application.ports.outbound.audit_publisher import AuditPublisher
from kingsec.application.ports.outbound.clock_port import ClockPort
from kingsec.application.submit_assessment import SubmitAssessment
from kingsec.application.use_cases.create_assessment import CreateAssessment
from kingsec.application.use_cases.create_schedule import CreateSchedule
from kingsec.application.use_cases.schedule_dto import CreateScheduleRequest
from kingsec.application.use_cases.submit_scheduled_assessment import SubmitScheduledAssessment
from kingsec.domain import Assessment, AssessmentId
from kingsec.domain.schedule import ScanSchedule
from kingsec.infrastructure.persistence.models import Base
from kingsec.infrastructure.persistence.repositories.schedule_occurrence import (
    SqlAlchemyScheduleOccurrenceRepository,
)
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


class FakeAssessmentRepository:
    """The same minimal in-memory fake established in test_submit_assessment.py."""

    def __init__(self) -> None:
        self._assessments: dict[str, Assessment] = {}
        self.saved: list[Assessment] = []

    def get(self, assessment_id: AssessmentId) -> Assessment:
        a = self._assessments.get(str(assessment_id))
        if a is None:
            raise AssessmentNotFoundError(str(assessment_id))
        return a

    def save(self, assessment: Assessment) -> None:
        self._assessments[str(assessment.id)] = assessment
        self.saved.append(assessment)

    def list(self, *, limit: int = 50, offset: int = 0) -> list[Assessment]:
        ordered = sorted(self._assessments.values(), key=lambda a: a.created_at, reverse=True)
        return ordered[offset : offset + limit]


class FakeScanner:
    def scan(self, target: Any, scanner_ids: Any = None) -> list:
        return []

    def compatible_scanners(self, target: Any) -> dict[str, str]:
        return {"fake": "Fake Scanner"}


class RecordingJobRunner:
    """Runs submitted jobs inline (synchronously) - see test_submit_assessment.py."""

    def __init__(self) -> None:
        self._jobs: dict[str, Any] = {}

    def submit(self, job_id: str, fn: Any, *args: Any, **kwargs: Any) -> None:
        self._jobs[job_id] = fn
        fn()

    def is_running(self, job_id: str) -> bool:
        return False

    def shutdown(self, wait: bool = True) -> None:
        pass


class _FinalizationFailsOnceRepo(SqlAlchemyScheduleRepository):
    """Wraps the real repository, injecting exactly one deterministic
    save() failure - simulating "the assessment was submitted, but the
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


def _make_schedule(repo: SqlAlchemyScheduleRepository, owner: str = "alice") -> str:
    create_uc = CreateSchedule(repo, _FakeAuditPublisher())
    result = create_uc.execute(
        CreateScheduleRequest(
            name="Nightly scan",
            owner_user_id=owner,
            target="10.0.0.77",
            cron_expression="0 2 * * *",
            schedule_type="cron",
        )
    )
    return result.schedule.id


def _make_scheduler(
    schedule_repo: SqlAlchemyScheduleRepository, session_factory
) -> tuple[InProcessScheduler, FakeAssessmentRepository]:
    occurrences = SqlAlchemyScheduleOccurrenceRepository(session_factory)
    assessments = FakeAssessmentRepository()
    create_assessment = CreateAssessment(assessments)
    submit_assessment = SubmitAssessment(assessments, FakeScanner(), RecordingJobRunner())
    orchestrator = SubmitScheduledAssessment(occurrences, create_assessment, submit_assessment)
    scheduler = InProcessScheduler(schedule_repo, orchestrator, _FakeClock())
    return scheduler, assessments


class TestResidualFinalizationFailureRaceIsNowFixed:
    def test_submission_success_plus_finalization_failure_does_not_duplicate_the_real_assessment(
        self, session_factory
    ) -> None:
        repo = _FinalizationFailsOnceRepo(session_factory)
        schedule_id = _make_schedule(repo)
        scheduler, assessments = _make_scheduler(repo, session_factory)

        # --- Cycle 1: the orchestrator succeeds (real assessment created
        # and submitted), finalization fails ---
        repo.save_failures_remaining = 1
        scheduler._poll_due_schedules()

        assert len(assessments.saved) >= 1, "cycle 1 must have created and submitted a real assessment"
        first_assessment_ids = {str(a.id) for a in assessments.list()}
        assert len(first_assessment_ids) == 1, "exactly one real assessment must exist after cycle 1"

        after_cycle_1 = repo.find_by_id(schedule_id)
        assert after_cycle_1.next_run is None, (
            "finalization failed, so next_run must remain unadvanced - the schedule is still due"
        )
        assert after_cycle_1.is_due("2030-01-01T00:00:00+00:00") is True

        # --- Cycle 2: a later, legitimate poll cycle re-claims the SAME
        # still-due occurrence (Phase 93's claim mechanism working exactly
        # as designed - this is not a bug in try_claim()). KSEC-98-01's
        # occurrence layer must find it already SUBMITTED and create
        # nothing new. ---
        scheduler._poll_due_schedules()

        second_assessment_ids = {str(a.id) for a in assessments.list()}
        assert second_assessment_ids == first_assessment_ids, (
            "cycle 2 must NOT have created a second real assessment for the same logical "
            "occurrence - this is the exact Phase 94/96 regression KSEC-98-01 exists to close"
        )
        after_cycle_2 = repo.find_by_id(schedule_id)
        assert after_cycle_2.next_run is not None, "cycle 2's finalization succeeded, advancing next_run normally"

    def test_a_second_recurrence_after_a_successful_cycle_is_a_legitimate_separate_occurrence(
        self, session_factory
    ) -> None:
        """KSEC-94-02: proves the flip side - once a cycle finalizes
        successfully and next_run genuinely advances, that new due window
        is a DIFFERENT, legitimate occurrence, and DOES get its own real
        assessment - the fix must never suppress legitimate recurrences."""
        repo = SqlAlchemyScheduleRepository(session_factory)
        schedule_id = _make_schedule(repo)
        scheduler, assessments = _make_scheduler(repo, session_factory)

        scheduler._poll_due_schedules()  # occurrence 1: succeeds normally
        after_first = repo.find_by_id(schedule_id)
        assert after_first.next_run is not None
        after_occurrence_1 = {str(a.id) for a in assessments.list()}
        assert len(after_occurrence_1) == 1

        # Force the schedule due again (simulating time passing to the
        # next legitimate cron firing) by directly relaxing next_run to
        # the past - a deterministic stand-in for "later," not a sleep.
        past_due = replace(after_first, next_run="2000-01-01T00:00:00")
        repo.save(past_due)

        scheduler._poll_due_schedules()  # occurrence 2: a genuinely new, later firing

        after_occurrence_2 = {str(a.id) for a in assessments.list()}
        assert len(after_occurrence_2) == 2, (
            "a genuinely new occurrence (a different next_run value) must produce its own "
            "real assessment - both are legitimate here, unlike the same-occurrence retry case above"
        )
        assert after_occurrence_1.issubset(after_occurrence_2)
        final = repo.find_by_id(schedule_id)
        assert final.next_run is not None
        assert final.next_run != "2000-01-01T00:00:00"
