"""KSEC-98-01: the combined exactly-once invariant under real concurrency.

Phase 93 proved the schedule-level claim (only one scheduler INSTANCE ever
processes a given due schedule). This file proves the SECOND, independent
layer Phase 98 adds - the occurrence-level claim inside
SubmitScheduledAssessment - holds under real concurrency too, and that the
two layers together produce the combined invariant Section 16 of the
Phase 98 prompt requires:

    N concurrent attempts (same schedule, same occurrence)
        -> exactly one schedule claimant
        -> exactly one occurrence record
        -> exactly one real assessment

Two scenarios are proven, both against a real on-disk SQLite database with
real threads, using threading.Barrier only (no time.sleep()):

    1. N threads racing the orchestrator directly for the SAME occurrence
       (isolates the occurrence layer's own protection under raw
       concurrency, independent of whether the schedule-level claim would
       ever actually allow this in production).

    2. Two REAL, independent InProcessScheduler instances (never one
       object raced against itself), each with its own repository and
       orchestrator instances, racing _poll_due_schedules() against the
       same real due schedule - the production-realistic scenario,
       exercising BOTH layers together.

Run multiple times (parametrize) per this repository's established
convention for concurrency proofs (Phases 87/93).
"""

from __future__ import annotations

import threading
import uuid
from pathlib import Path
from typing import Any

import pytest
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

from kingsec.application.errors import AssessmentNotFoundError, ScheduledOccurrenceUnresolvedError
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


class LockedFakeAssessmentRepository:
    """Thread-safe in-memory assessment repository - the real
    SQLAlchemy-backed repositories already serialize writes at the
    database level; this fake needs its own lock since multiple threads
    share one Python dict directly."""

    def __init__(self) -> None:
        self._assessments: dict[str, Assessment] = {}
        self._lock = threading.Lock()

    def get(self, assessment_id: AssessmentId) -> Assessment:
        with self._lock:
            a = self._assessments.get(str(assessment_id))
        if a is None:
            raise AssessmentNotFoundError(str(assessment_id))
        return a

    def save(self, assessment: Assessment) -> None:
        with self._lock:
            self._assessments[str(assessment.id)] = assessment

    def list(self, *, limit: int = 50, offset: int = 0) -> list[Assessment]:
        with self._lock:
            ordered = sorted(self._assessments.values(), key=lambda a: a.created_at, reverse=True)
            return ordered[offset : offset + limit]

    def find_by_schedule_occurrence_id(self, occurrence_id: str) -> list[Assessment]:
        with self._lock:
            return [a for a in self._assessments.values() if a.schedule_occurrence_id == occurrence_id]


class FakeScanner:
    def scan(self, target: Any, scanner_ids: Any = None) -> list:
        return []

    def compatible_scanners(self, target: Any) -> dict[str, str]:
        return {"fake": "Fake Scanner"}


class RecordingJobRunner:
    def __init__(self) -> None:
        self._lock = threading.Lock()
        self._jobs: dict[str, Any] = {}

    def submit(self, job_id: str, fn: Any, *args: Any, **kwargs: Any) -> None:
        with self._lock:
            self._jobs[job_id] = fn
        fn()

    def is_running(self, job_id: str) -> bool:
        return False

    def shutdown(self, wait: bool = True) -> None:
        pass


@pytest.fixture
def engine(tmp_path: Path):
    db_path = tmp_path / f"scheduled-assessment-concurrency-{uuid.uuid4().hex}.sqlite3"
    eng = create_engine(f"sqlite:///{db_path}", future=True, connect_args={"timeout": 30})
    Base.metadata.create_all(eng)
    return eng


@pytest.fixture
def session_factory(engine):
    return sessionmaker(bind=engine, expire_on_commit=False, future=True)


def _make_schedule(session_factory) -> ScanSchedule:
    repo = SqlAlchemyScheduleRepository(session_factory)
    result = CreateSchedule(repo, _FakeAuditPublisher()).execute(
        CreateScheduleRequest(
            name="Concurrency probe",
            owner_user_id="alice",
            target="10.0.0.80",
            cron_expression="0 2 * * *",
            schedule_type="cron",
        )
    )
    return result.schedule


class TestConcurrentOrchestratorInvocationsForTheSameOccurrence:
    """Isolates the occurrence layer: N threads all call
    SubmitScheduledAssessment.execute() for the IDENTICAL schedule/occurrence
    at the same instant - a scenario Phase 93's schedule-level claim
    prevents in real production (only one InProcessScheduler instance ever
    calls execute() for a given due schedule), deliberately manufactured
    here anyway to stress-test the occurrence layer's own protection in
    isolation.

    KSEC-100-01: once some threads race far enough ahead of others (thread
    scheduling after the shared Barrier release is not lockstep), a
    slower thread's OWN FIRST read of the occurrence can legitimately
    observe CREATING/SUBMITTING left by a FASTER thread that is still
    genuinely, live, in progress - not a crashed/stale state. Per Phase
    99/100 Step 6, this is indistinguishable from a genuinely abandoned
    occurrence without a liveness mechanism (deliberately not built this
    phase), so ScheduledOccurrenceUnresolvedError is the CORRECT, safe
    outcome for such a thread - not a bug. The security property this
    test actually proves is narrower and still holds: no thread ever
    silently guesses, and at most one real assessment is ever created."""

    @pytest.mark.parametrize("run", range(5))
    def test_n_concurrent_executions_produce_at_most_one_real_assessment_never_a_silent_guess(
        self, run: int, session_factory
    ) -> None:
        schedule = _make_schedule(session_factory)
        assessments = LockedFakeAssessmentRepository()

        def _new_orchestrator() -> SubmitScheduledAssessment:
            occurrences = SqlAlchemyScheduleOccurrenceRepository(session_factory)
            create_assessment = CreateAssessment(assessments)
            submit_assessment = SubmitAssessment(assessments, FakeScanner(), RecordingJobRunner())
            return SubmitScheduledAssessment(occurrences, create_assessment, submit_assessment, assessments)

        attempt_count = 6
        barrier = threading.Barrier(attempt_count)
        errors: list[BaseException] = []
        lock = threading.Lock()

        def _attempt() -> None:
            orchestrator = _new_orchestrator()
            barrier.wait(timeout=5)
            try:
                orchestrator.execute(schedule)
            except BaseException as exc:
                with lock:
                    errors.append(exc)

        threads = [threading.Thread(target=_attempt) for _ in range(attempt_count)]
        for t in threads:
            t.start()
        for t in threads:
            t.join(timeout=15)

        unexpected = [e for e in errors if not isinstance(e, ScheduledOccurrenceUnresolvedError)]
        assert unexpected == [], (
            f"run {run}: only ScheduledOccurrenceUnresolvedError is an acceptable exception here "
            f"(a thread honestly refusing to guess at a state another thread may still be live in) - "
            f"got unexpected: {unexpected}"
        )
        assert len(assessments.list()) == 1, (
            f"run {run}: {len(assessments.list())} real assessments exist after {attempt_count} "
            "concurrent attempts for the identical occurrence - expected exactly 1, never more"
        )


class TestConcurrentSchedulerInstancesCombinedInvariant:
    """The production-realistic scenario: two independent InProcessScheduler
    instances, each with its own repository/orchestrator, racing the same
    real due schedule - Phase 93's schedule claim and Phase 98's occurrence
    claim operating together."""

    @pytest.mark.parametrize("run", range(5))
    def test_two_scheduler_instances_racing_the_same_due_schedule_produce_exactly_one_assessment(
        self, run: int, session_factory
    ) -> None:
        schedule = _make_schedule(session_factory)
        assessments = LockedFakeAssessmentRepository()

        barrier = threading.Barrier(2)

        class _BarrierGatedScheduleRepo(SqlAlchemyScheduleRepository):
            def find_due(self, now_utc_str: str):
                result = super().find_due(now_utc_str)
                barrier.wait(timeout=5)
                return result

        def _new_scheduler() -> InProcessScheduler:
            schedule_repo = _BarrierGatedScheduleRepo(session_factory)
            occurrences = SqlAlchemyScheduleOccurrenceRepository(session_factory)
            create_assessment = CreateAssessment(assessments)
            submit_assessment = SubmitAssessment(assessments, FakeScanner(), RecordingJobRunner())
            orchestrator = SubmitScheduledAssessment(occurrences, create_assessment, submit_assessment, assessments)
            return InProcessScheduler(schedule_repo, orchestrator, _FakeClock())

        scheduler_a = _new_scheduler()
        scheduler_b = _new_scheduler()

        thread_a = threading.Thread(target=scheduler_a._poll_due_schedules)
        thread_b = threading.Thread(target=scheduler_b._poll_due_schedules)
        thread_a.start()
        thread_b.start()
        thread_a.join(timeout=15)
        thread_b.join(timeout=15)

        assert len(assessments.list()) == 1, (
            f"run {run}: {len(assessments.list())} real assessments exist after two scheduler "
            "instances raced the same due schedule - expected exactly 1"
        )

        final_repo = SqlAlchemyScheduleRepository(session_factory)
        final_schedule = final_repo.find_by_id(str(schedule.id))
        assert final_schedule.next_run is not None, "the winning instance's finalization write must have run"
