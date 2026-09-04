"""KSEC-100-01: safe CREATING recovery, and the fix for silent schedule
finalization over an abandoned occurrence.

Real on-disk SQLite throughout, including the real
LegacyAssessmentRepository (production's own AssessmentRepository
implementation) - so ``find_by_schedule_occurrence_id()``'s actual SQL is
exercised, not a hand-written duck-typed approximation of it. Only
ScannerPort/JobRunner are fakes (no scanner binaries, no threads -
RecordingJobRunner runs inline, matching every sibling Phase 98/99 test
file's established convention). No sleeps for correctness anywhere -
concurrency proofs use threading.Barrier only.
"""

from __future__ import annotations

import threading
import uuid
from pathlib import Path
from typing import Any

import pytest
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

from kingsec.application.dto import CreateAssessmentRequest, SubmitAssessmentRequest
from kingsec.application.errors import ScheduledOccurrenceUnresolvedError
from kingsec.application.ports.outbound.audit_publisher import AuditPublisher
from kingsec.application.ports.outbound.clock_port import ClockPort
from kingsec.application.schedule_occurrence import OccurrenceStatus
from kingsec.application.submit_assessment import SubmitAssessment
from kingsec.application.use_cases.create_assessment import CreateAssessment
from kingsec.application.use_cases.create_schedule import CreateSchedule
from kingsec.application.use_cases.schedule_dto import CreateScheduleRequest
from kingsec.application.use_cases.submit_scheduled_assessment import (
    SCHEDULER_SERVICE_USER_ID,
    ScheduledAssessmentOutcome,
    SubmitScheduledAssessment,
    derive_occurrence_key,
)
from kingsec.domain.audit import AuditAction
from kingsec.domain.identifiers import AssessmentId
from kingsec.domain.schedule import ScanSchedule
from kingsec.infrastructure.persistence._legacy_repositories import LegacyAssessmentRepository
from kingsec.infrastructure.persistence.models import Base
from kingsec.infrastructure.persistence.repositories.schedule_occurrence import (
    SqlAlchemyScheduleOccurrenceRepository,
)
from kingsec.infrastructure.scheduler.in_process_scheduler import InProcessScheduler
from kingsec.infrastructure.scheduler.sqlalchemy_schedule_repository import SqlAlchemyScheduleRepository


class _RecordingAuditPublisher(AuditPublisher):
    def __init__(self) -> None:
        self.entries: list = []

    def record(self, entry) -> None:
        self.entries.append(entry)


class _FakeClock(ClockPort):
    def now(self) -> float:
        return 0.0


class FakeScanner:
    def scan(self, target: Any, scanner_ids: Any = None) -> list:
        return []

    def compatible_scanners(self, target: Any) -> dict[str, str]:
        return {"fake": "Fake Scanner"}


class RecordingJobRunner:
    def submit(self, job_id: str, fn: Any, *args: Any, **kwargs: Any) -> None:
        fn()

    def is_running(self, job_id: str) -> bool:
        return False

    def shutdown(self, wait: bool = True) -> None:
        pass


class NonInlineJobRunner:
    """Accepts the submitted background work but never runs it - leaves
    the assessment durably at RUNNING (SubmitAssessment's own synchronous
    save()) with no further transition, exactly matching Phase 99's
    Crash D evidence (ThreadJobRunner's real work happens asynchronously,
    after execute() has already returned)."""

    def submit(self, job_id: str, fn: Any, *args: Any, **kwargs: Any) -> None:
        pass

    def is_running(self, job_id: str) -> bool:
        return False

    def shutdown(self, wait: bool = True) -> None:
        pass


@pytest.fixture
def engine(tmp_path: Path):
    db_path = tmp_path / f"scheduled-recovery-{uuid.uuid4().hex}.sqlite3"
    eng = create_engine(f"sqlite:///{db_path}", future=True, connect_args={"timeout": 30})
    Base.metadata.create_all(eng)
    return eng


@pytest.fixture
def session_factory(engine):
    return sessionmaker(bind=engine, expire_on_commit=False, future=True)


def _make_schedule(session_factory, owner: str = "alice") -> ScanSchedule:
    repo = SqlAlchemyScheduleRepository(session_factory)
    result = CreateSchedule(repo, _RecordingAuditPublisher()).execute(
        CreateScheduleRequest(
            name="Recovery probe",
            owner_user_id=owner,
            target="10.0.0.90",
            cron_expression="0 2 * * *",
            schedule_type="cron",
        )
    )
    return result.schedule


def _build(session_factory, audit: AuditPublisher | None = None):
    occurrences = SqlAlchemyScheduleOccurrenceRepository(session_factory)
    assessments = LegacyAssessmentRepository(session_factory)
    create_assessment = CreateAssessment(assessments)
    submit_assessment = SubmitAssessment(assessments, FakeScanner(), RecordingJobRunner())
    orchestrator = SubmitScheduledAssessment(occurrences, create_assessment, submit_assessment, assessments, audit)
    return orchestrator, occurrences, assessments


class TestCreatingRecoveryNoLinkedAssessment:
    """Case A: crashed before CreateAssessment ever committed - no
    evidence exists, so recovery must refuse, not guess."""

    def test_raises_unresolved_and_creates_no_assessment(self, session_factory) -> None:
        schedule = _make_schedule(session_factory)
        audit = _RecordingAuditPublisher()
        orchestrator, occurrences, assessments = _build(session_factory, audit)

        # Manually drive CLAIMED -> CREATING, simulating a crash before
        # CreateAssessment was ever called (Phase 99 Crash A).
        occ = occurrences.try_claim(str(schedule.id), derive_occurrence_key(schedule))
        locked = occurrences.try_begin_creation(occ.id, occ.version)
        assert locked is not None

        with pytest.raises(ScheduledOccurrenceUnresolvedError):
            orchestrator.execute(schedule)

        assert assessments.list() == []
        unresolved_entries = [e for e in audit.entries if e.action == AuditAction.SCHEDULE_OCCURRENCE_UNRESOLVED]
        assert len(unresolved_entries) == 1
        assert "no linked assessment" in unresolved_entries[0].reason


class TestCreatingRecoveryOneAuthorizedAssessment:
    """Case B: CreateAssessment committed before the crash - the durable
    link proves it, so recovery may safely proceed without calling
    CreateAssessment again."""

    def test_recovers_and_completes_without_duplicating(self, session_factory) -> None:
        schedule = _make_schedule(session_factory, owner="bob")
        orchestrator, occurrences, assessments = _build(session_factory)

        occ = occurrences.try_claim(str(schedule.id), derive_occurrence_key(schedule))
        locked = occurrences.try_begin_creation(occ.id, occ.version)
        assert locked is not None

        # Simulate CreateAssessment having committed before the crash,
        # via the real use case (not a hand-crafted row) - exactly Phase
        # 99's crash_after_create_commit scenario, minus the process kill.
        create_result = CreateAssessment(assessments).execute(
            CreateAssessmentRequest(
                target_value=schedule.target,
                target_type="ip_address",
                authorized_by=schedule.owner_user_id,
                scope=schedule.name,
                owner_id=SCHEDULER_SERVICE_USER_ID,
                schedule_occurrence_id=occ.id,
            )
        )
        # Deliberately do NOT call mark_assessment_created() - the
        # occurrence remains stuck at CREATING, exactly as Phase 99 found.

        result = orchestrator.execute(schedule)

        assert result.outcome == ScheduledAssessmentOutcome.SUBMITTED
        assert result.assessment_id == create_result.assessment_id
        assert len(assessments.list()) == 1, "recovery must not create a second assessment"

    def test_concurrent_recovery_attempts_produce_no_duplicate(self, session_factory) -> None:
        """Multiple recovery attempts (e.g. two scheduler instances both
        reaching a stuck CREATING occurrence) racing the SAME evidence
        must still produce exactly one real outcome - real threads, real
        on-disk SQLite, a Barrier, no sleeps."""
        schedule = _make_schedule(session_factory)
        occurrences_seed = SqlAlchemyScheduleOccurrenceRepository(session_factory)
        assessments_seed = LegacyAssessmentRepository(session_factory)

        occ = occurrences_seed.try_claim(str(schedule.id), derive_occurrence_key(schedule))
        locked = occurrences_seed.try_begin_creation(occ.id, occ.version)
        assert locked is not None
        create_result = CreateAssessment(assessments_seed).execute(
            CreateAssessmentRequest(
                target_value=schedule.target,
                target_type="ip_address",
                authorized_by=schedule.owner_user_id,
                scope=schedule.name,
                owner_id=SCHEDULER_SERVICE_USER_ID,
                schedule_occurrence_id=occ.id,
            )
        )

        attempt_count = 6
        barrier = threading.Barrier(attempt_count)
        errors: list[BaseException] = []
        outcomes: list[str] = []
        lock = threading.Lock()

        def _attempt() -> None:
            orchestrator, _, _ = _build(session_factory)
            barrier.wait(timeout=5)
            try:
                result = orchestrator.execute(schedule)
                with lock:
                    outcomes.append(result.outcome)
            except BaseException as exc:
                with lock:
                    errors.append(exc)

        threads = [threading.Thread(target=_attempt) for _ in range(attempt_count)]
        for t in threads:
            t.start()
        for t in threads:
            t.join(timeout=15)

        # A thread that races far enough ahead of others (post-Barrier
        # thread scheduling is not lockstep) can legitimately observe a
        # sibling's own SUBMITTING state via its OWN fresh try_claim() -
        # indistinguishable from a stale one without a liveness mechanism
        # (Phase 99/100), so ScheduledOccurrenceUnresolvedError is a
        # correct, honest outcome here too, not a bug.
        unexpected = [e for e in errors if not isinstance(e, ScheduledOccurrenceUnresolvedError)]
        assert unexpected == [], f"only ScheduledOccurrenceUnresolvedError is acceptable - got {unexpected}"
        assert len(outcomes) + len(errors) == attempt_count
        assert ScheduledAssessmentOutcome.SUBMITTED in outcomes, "at least one attempt must have completed the recovery"

        final_assessments = LegacyAssessmentRepository(session_factory).list()
        assert len(final_assessments) == 1, (
            f"{len(final_assessments)} real assessments exist after {attempt_count} concurrent "
            "recovery attempts against the same evidence - expected exactly 1"
        )
        assert final_assessments[0].id.value == create_result.assessment_id


class TestCreatingRecoveryMultipleLinkedAssessments:
    """Step 8: a corrupted/ambiguous state - never silently pick one."""

    def test_raises_unresolved_and_modifies_nothing(self, session_factory) -> None:
        schedule = _make_schedule(session_factory)
        orchestrator, occurrences, assessments = _build(session_factory)

        occ = occurrences.try_claim(str(schedule.id), derive_occurrence_key(schedule))
        locked = occurrences.try_begin_creation(occ.id, occ.version)
        assert locked is not None

        # Two independent CreateAssessment calls linked to the SAME
        # occurrence - simulating historical corruption (Step 8), not a
        # scenario the current single-threaded flow can itself reach.
        first = CreateAssessment(assessments).execute(
            CreateAssessmentRequest(
                target_value=schedule.target,
                target_type="ip_address",
                authorized_by=schedule.owner_user_id,
                scope=schedule.name,
                owner_id=SCHEDULER_SERVICE_USER_ID,
                schedule_occurrence_id=occ.id,
            )
        )
        second = CreateAssessment(assessments).execute(
            CreateAssessmentRequest(
                target_value=schedule.target,
                target_type="ip_address",
                authorized_by=schedule.owner_user_id,
                scope=schedule.name,
                owner_id=SCHEDULER_SERVICE_USER_ID,
                schedule_occurrence_id=occ.id,
            )
        )

        with pytest.raises(ScheduledOccurrenceUnresolvedError, match="ambiguous"):
            orchestrator.execute(schedule)

        before_ids = {first.assessment_id, second.assessment_id}
        after_ids = {str(a.id) for a in assessments.list()}
        assert after_ids == before_ids, "neither existing assessment must be modified"
        refreshed = occurrences.try_claim(str(schedule.id), derive_occurrence_key(schedule))
        assert refreshed.status == OccurrenceStatus.CREATING, "the occurrence must not be silently advanced"


class TestCreatingRecoveryUnexpectedAssessmentStatus:
    """Step 9: a linked assessment with a status other than AUTHORIZED is
    internally inconsistent with an occurrence still claiming CREATING -
    never guessed at."""

    @pytest.mark.parametrize("target_status", ["RUNNING", "COMPLETED", "FAILED"])
    def test_raises_unresolved_for_non_authorized_status(self, session_factory, target_status: str) -> None:
        schedule = _make_schedule(session_factory)
        orchestrator, occurrences, assessments = _build(session_factory)

        occ = occurrences.try_claim(str(schedule.id), derive_occurrence_key(schedule))
        locked = occurrences.try_begin_creation(occ.id, occ.version)
        assert locked is not None

        create_result = CreateAssessment(assessments).execute(
            CreateAssessmentRequest(
                target_value=schedule.target,
                target_type="ip_address",
                authorized_by=schedule.owner_user_id,
                scope=schedule.name,
                owner_id=SCHEDULER_SERVICE_USER_ID,
                schedule_occurrence_id=occ.id,
            )
        )
        # Advance the assessment past AUTHORIZED via the real use case
        # (SubmitAssessment), then optionally further, to reach the
        # target status under test - never hand-crafted. NonInlineJobRunner
        # ensures the assessment stops exactly at RUNNING (the background
        # scan never actually runs), matching Phase 99's Crash D evidence.
        SubmitAssessment(assessments, FakeScanner(), NonInlineJobRunner()).execute(
            SubmitAssessmentRequest(assessment_id=create_result.assessment_id, requesting_user=SCHEDULER_SERVICE_USER_ID)
        )
        if target_status in ("COMPLETED", "FAILED"):
            assessment = assessments.get(AssessmentId(create_result.assessment_id))
            if target_status == "COMPLETED":
                assessment.complete()
            else:
                assessment.fail("simulated failure for KSEC-100-01 test")
            assessments.save(assessment)

        with pytest.raises(ScheduledOccurrenceUnresolvedError, match="ambiguous"):
            orchestrator.execute(schedule)


class TestSubmittingNeverAutoRecovered:
    """Step 13: SUBMITTING must never be automatically resumed or
    resubmitted, regardless of the linked assessment's status - there is
    no durable execution ledger to prove whether ThreadJobRunner actually
    ran the scan."""

    @pytest.mark.parametrize("via_full_flow", [True])
    def test_submitting_always_raises_unresolved(self, session_factory, via_full_flow: bool) -> None:
        schedule = _make_schedule(session_factory)
        audit = _RecordingAuditPublisher()
        orchestrator, occurrences, assessments = _build(session_factory, audit)

        occ = occurrences.try_claim(str(schedule.id), derive_occurrence_key(schedule))
        locked = occurrences.try_begin_creation(occ.id, occ.version)
        assert locked is not None
        create_result = CreateAssessment(assessments).execute(
            CreateAssessmentRequest(
                target_value=schedule.target,
                target_type="ip_address",
                authorized_by=schedule.owner_user_id,
                scope=schedule.name,
                owner_id=SCHEDULER_SERVICE_USER_ID,
                schedule_occurrence_id=occ.id,
            )
        )
        occurrences.mark_assessment_created(occ.id, locked, create_result.assessment_id)
        after_create = occurrences.try_claim(str(schedule.id), derive_occurrence_key(schedule))
        locked2 = occurrences.try_begin_submission(occ.id, after_create.version)
        assert locked2 is not None
        # SubmitAssessment's own synchronous save() commits RUNNING -
        # exactly Phase 99's Crash D evidence: durable RUNNING, no
        # durable proof the background scan itself ever ran.
        SubmitAssessment(assessments, FakeScanner(), RecordingJobRunner()).execute(
            SubmitAssessmentRequest(assessment_id=create_result.assessment_id, requesting_user=SCHEDULER_SERVICE_USER_ID)
        )
        # Deliberately do NOT call mark_submitted() - stuck at SUBMITTING.

        with pytest.raises(ScheduledOccurrenceUnresolvedError):
            orchestrator.execute(schedule)

        unresolved_entries = [e for e in audit.entries if e.action == AuditAction.SCHEDULE_OCCURRENCE_UNRESOLVED]
        assert len(unresolved_entries) == 1
        assert "SUBMITTING" in unresolved_entries[0].reason


class TestSchedulerDoesNotSilentlyFinalizeAnAbandonedOccurrence:
    """Step 10/11: the key invariant - a scheduled occurrence may advance
    to its next recurrence only when the current occurrence is
    demonstrably handled or safely finalized. Uses the REAL
    InProcessScheduler and its actual _poll_due_schedules()."""

    def _scheduler_for(self, schedule_repo, session_factory, audit=None):
        orchestrator, occurrences, assessments = _build(session_factory, audit)
        return InProcessScheduler(schedule_repo, orchestrator, _FakeClock()), occurrences, assessments

    def test_creating_with_no_assessment_does_not_advance_next_run(self, session_factory) -> None:
        schedule_repo = SqlAlchemyScheduleRepository(session_factory)
        schedule = _make_schedule(session_factory)
        scheduler, occurrences, _ = self._scheduler_for(schedule_repo, session_factory)

        # Pre-seed a stuck CREATING occurrence (no assessment) for the
        # SAME occurrence key the scheduler's own poll cycle will derive.
        occ = occurrences.try_claim(str(schedule.id), derive_occurrence_key(schedule))
        locked = occurrences.try_begin_creation(occ.id, occ.version)
        assert locked is not None

        scheduler._poll_due_schedules()

        after = schedule_repo.find_by_id(str(schedule.id))
        assert after.next_run is None, "next_run must NOT advance over an abandoned CREATING occurrence"
        assert after.is_due("2030-01-01T00:00:00+00:00") is True

    def test_submitting_does_not_advance_next_run(self, session_factory) -> None:
        schedule_repo = SqlAlchemyScheduleRepository(session_factory)
        schedule = _make_schedule(session_factory)
        scheduler, occurrences, assessments = self._scheduler_for(schedule_repo, session_factory)

        occ = occurrences.try_claim(str(schedule.id), derive_occurrence_key(schedule))
        locked = occurrences.try_begin_creation(occ.id, occ.version)
        assert locked is not None
        create_result = CreateAssessment(assessments).execute(
            CreateAssessmentRequest(
                target_value=schedule.target,
                target_type="ip_address",
                authorized_by=schedule.owner_user_id,
                scope=schedule.name,
                owner_id=SCHEDULER_SERVICE_USER_ID,
                schedule_occurrence_id=occ.id,
            )
        )
        occurrences.mark_assessment_created(occ.id, locked, create_result.assessment_id)
        after_create = occurrences.try_claim(str(schedule.id), derive_occurrence_key(schedule))
        occurrences.try_begin_submission(occ.id, after_create.version)

        scheduler._poll_due_schedules()

        after = schedule_repo.find_by_id(str(schedule.id))
        assert after.next_run is None, "next_run must NOT advance over an abandoned SUBMITTING occurrence"

    def test_submitted_occurrence_finalizes_normally(self, session_factory) -> None:
        schedule_repo = SqlAlchemyScheduleRepository(session_factory)
        schedule = _make_schedule(session_factory)
        scheduler, occurrences, assessments = self._scheduler_for(schedule_repo, session_factory)

        occ = occurrences.try_claim(str(schedule.id), derive_occurrence_key(schedule))
        locked = occurrences.try_begin_creation(occ.id, occ.version)
        assert locked is not None
        create_result = CreateAssessment(assessments).execute(
            CreateAssessmentRequest(
                target_value=schedule.target,
                target_type="ip_address",
                authorized_by=schedule.owner_user_id,
                scope=schedule.name,
                owner_id=SCHEDULER_SERVICE_USER_ID,
                schedule_occurrence_id=occ.id,
            )
        )
        occurrences.mark_assessment_created(occ.id, locked, create_result.assessment_id)
        after_create = occurrences.try_claim(str(schedule.id), derive_occurrence_key(schedule))
        locked2 = occurrences.try_begin_submission(occ.id, after_create.version)
        SubmitAssessment(assessments, FakeScanner(), RecordingJobRunner()).execute(
            SubmitAssessmentRequest(assessment_id=create_result.assessment_id, requesting_user=SCHEDULER_SERVICE_USER_ID)
        )
        occurrences.mark_submitted(occ.id, locked2)

        scheduler._poll_due_schedules()

        after = schedule_repo.find_by_id(str(schedule.id))
        assert after.next_run is not None, "a genuinely SUBMITTED occurrence must finalize normally"
        assert len(assessments.list()) == 1

    def test_normal_successful_execution_finalizes_normally(self, session_factory) -> None:
        schedule_repo = SqlAlchemyScheduleRepository(session_factory)
        schedule = _make_schedule(session_factory)
        scheduler, _occurrences, assessments = self._scheduler_for(schedule_repo, session_factory)

        scheduler._poll_due_schedules()

        after = schedule_repo.find_by_id(str(schedule.id))
        assert after.next_run is not None, "a normal, uninterrupted poll cycle must finalize normally"
        assert len(assessments.list()) == 1
