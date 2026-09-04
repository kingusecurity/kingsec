"""KSEC-98-01: SubmitScheduledAssessment - scheduler identity, narrow
authorization, and occurrence-scoped failure/retry semantics.

Real SqlAlchemyScheduleOccurrenceRepository (on-disk SQLite) throughout, so
the occurrence state machine under test is the real one, not a parallel
fake that could drift from it. CreateAssessment/SubmitAssessment are also
real; only ScannerPort/JobRunner are fakes (no scanner binaries, no
threads - RecordingJobRunner runs inline) - the exact FakeScanner/
RecordingJobRunner shape already established in test_submit_assessment.py.
"""

from __future__ import annotations

import uuid
from pathlib import Path
from typing import Any

import pytest
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

from kingsec.application._support import check_assessment_access
from kingsec.application.dto import CreateAssessmentRequest, SubmitAssessmentRequest
from kingsec.application.errors import AssessmentNotFoundError
from kingsec.application.submit_assessment import SubmitAssessment
from kingsec.application.use_cases.create_assessment import CreateAssessment
from kingsec.application.use_cases.create_schedule import CreateSchedule
from kingsec.application.use_cases.schedule_dto import CreateScheduleRequest
from kingsec.application.use_cases.submit_scheduled_assessment import (
    SCHEDULER_SERVICE_USER_ID,
    SCHEDULER_SERVICE_USERNAME,
    ScheduledAssessmentOutcome,
    SubmitScheduledAssessment,
    _detect_target_type,
    derive_occurrence_key,
)
from kingsec.domain import Assessment, AssessmentId
from kingsec.domain.audit import AuditEntry
from kingsec.domain.schedule import ScanSchedule
from kingsec.infrastructure.persistence.models import Base
from kingsec.infrastructure.persistence.repositories.schedule_occurrence import (
    SqlAlchemyScheduleOccurrenceRepository,
)
from kingsec.infrastructure.scheduler.sqlalchemy_schedule_repository import SqlAlchemyScheduleRepository


class FakeAssessmentRepository:
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

    def find_by_schedule_occurrence_id(self, occurrence_id: str) -> list[Assessment]:
        return [a for a in self._assessments.values() if a.schedule_occurrence_id == occurrence_id]


class FakeScanner:
    def scan(self, target: Any, scanner_ids: Any = None) -> list:
        return []

    def compatible_scanners(self, target: Any) -> dict[str, str]:
        return {"fake": "Fake Scanner"}


class RecordingJobRunner:
    def __init__(self) -> None:
        self._jobs: dict[str, Any] = {}

    def submit(self, job_id: str, fn: Any, *args: Any, **kwargs: Any) -> None:
        self._jobs[job_id] = fn
        fn()

    def is_running(self, job_id: str) -> bool:
        return False

    def shutdown(self, wait: bool = True) -> None:
        pass


class _FakeAuditPublisher:
    def __init__(self) -> None:
        self.entries: list[AuditEntry] = []

    def record(self, entry: AuditEntry) -> None:
        self.entries.append(entry)


class _RaisesOnceCreateAssessment:
    """Wraps a real CreateAssessment, raising exactly once (Case A)."""

    def __init__(self, inner: CreateAssessment) -> None:
        self._inner = inner
        self.failures_remaining = 0
        self.call_count = 0

    def execute(self, request: CreateAssessmentRequest):
        self.call_count += 1
        if self.failures_remaining > 0:
            self.failures_remaining -= 1
            raise RuntimeError("simulated CreateAssessment failure (Case A)")
        return self._inner.execute(request)


class _RaisesOnceSubmitAssessment:
    """Wraps a real SubmitAssessment, raising exactly once (Case B)."""

    def __init__(self, inner: SubmitAssessment) -> None:
        self._inner = inner
        self.failures_remaining = 0
        self.call_count = 0

    def execute(self, request: SubmitAssessmentRequest):
        self.call_count += 1
        if self.failures_remaining > 0:
            self.failures_remaining -= 1
            raise RuntimeError("simulated SubmitAssessment failure (Case B)")
        return self._inner.execute(request)


@pytest.fixture
def engine(tmp_path: Path):
    db_path = tmp_path / f"submit-scheduled-{uuid.uuid4().hex}.sqlite3"
    eng = create_engine(f"sqlite:///{db_path}", future=True, connect_args={"timeout": 30})
    Base.metadata.create_all(eng)
    return eng


@pytest.fixture
def session_factory(engine):
    return sessionmaker(bind=engine, expire_on_commit=False, future=True)


def _make_schedule(session_factory, owner: str = "real-human-user") -> ScanSchedule:
    repo = SqlAlchemyScheduleRepository(session_factory)
    result = CreateSchedule(repo, _FakeAuditPublisher()).execute(
        CreateScheduleRequest(
            name="Nightly external scan",
            owner_user_id=owner,
            target="10.0.0.50",
            cron_expression="0 2 * * *",
            schedule_type="cron",
        )
    )
    return result.schedule


def _build_orchestrator(session_factory) -> tuple[SubmitScheduledAssessment, FakeAssessmentRepository]:
    occurrences = SqlAlchemyScheduleOccurrenceRepository(session_factory)
    assessments = FakeAssessmentRepository()
    create_assessment = CreateAssessment(assessments)
    submit_assessment = SubmitAssessment(assessments, FakeScanner(), RecordingJobRunner())
    orchestrator = SubmitScheduledAssessment(occurrences, create_assessment, submit_assessment, assessments)
    return orchestrator, assessments


class TestOccurrenceKeyDerivation:
    def test_uses_next_run_verbatim_when_present(self) -> None:
        schedule = _fake_schedule(next_run="2026-09-05T04:00:00")
        assert derive_occurrence_key(schedule) == "2026-09-05T04:00:00"

    def test_uses_sentinel_when_next_run_is_none(self) -> None:
        schedule = _fake_schedule(next_run=None)
        assert derive_occurrence_key(schedule) == "__initial__"


class TestTargetTypeDetection:
    @pytest.mark.parametrize(
        ("target", "expected"),
        [
            ("scan-me.example.com", "hostname"),
            ("10.0.0.5", "ip_address"),
            ("10.0.0.0/24", "network"),
            ("https://example.com/", "url"),
            ("http://example.com/", "url"),
        ],
    )
    def test_detects_the_expected_type(self, target: str, expected: str) -> None:
        assert _detect_target_type(target) == expected


class TestSchedulerIdentity:
    def test_owner_is_the_scheduler_service_identity_not_the_schedule_owner(self, session_factory) -> None:
        schedule = _make_schedule(session_factory, owner="alice")
        orchestrator, assessments = _build_orchestrator(session_factory)

        orchestrator.execute(schedule)

        assert len(assessments.saved) >= 1
        assessment = assessments.list()[0]
        assert assessment.owner_id == SCHEDULER_SERVICE_USER_ID
        assert assessment.owner_id != "alice"

    def test_authorized_by_preserves_the_real_schedule_owner(self, session_factory) -> None:
        """KSEC-98-01 Section 4: executed_by (scheduler service) and
        schedule owner (the real human) must both be recoverable, never
        collapsed into one field."""
        schedule = _make_schedule(session_factory, owner="alice")
        orchestrator, assessments = _build_orchestrator(session_factory)

        orchestrator.execute(schedule)

        assessment = assessments.list()[0]
        assert assessment.authorization is not None
        assert assessment.authorization.authorized_by == "alice"

    def test_scheduler_identity_cannot_access_an_arbitrary_pre_existing_assessment(
        self, session_factory
    ) -> None:
        """The required security property (Phase 98 Section 3/12): the
        scheduler identity must NOT be able to use the scheduled
        authorization mechanism to reach an assessment it did not create -
        no blanket is_admin=True, no broadened access."""
        assessments = FakeAssessmentRepository()
        human_assessment = CreateAssessment(assessments).execute(
            CreateAssessmentRequest(
                target_value="10.0.0.60",
                target_type="ip_address",
                authorized_by="alice",
                scope="alice's own manual assessment",
                owner_id="alice",
            )
        )

        submit_assessment = SubmitAssessment(assessments, FakeScanner(), RecordingJobRunner())
        with pytest.raises(AssessmentNotFoundError):
            submit_assessment.execute(
                SubmitAssessmentRequest(
                    assessment_id=human_assessment.assessment_id,
                    requesting_user=SCHEDULER_SERVICE_USER_ID,
                    requesting_username=SCHEDULER_SERVICE_USERNAME,
                    is_admin=False,
                )
            )

    def test_manual_user_authorization_is_unaffected(self) -> None:
        """Regression sanity check (Phase 98 Section 17): the ordinary
        ownership rule real users rely on is untouched by adding the
        scheduler identity."""
        assessments = FakeAssessmentRepository()
        result = CreateAssessment(assessments).execute(
            CreateAssessmentRequest(
                target_value="10.0.0.61",
                target_type="ip_address",
                authorized_by="bob",
                scope="bob's own manual assessment",
                owner_id="bob",
            )
        )
        assessment = assessments.get(AssessmentId(result.assessment_id))

        check_assessment_access(assessment, "bob", is_admin=False)  # must not raise

        with pytest.raises(AssessmentNotFoundError):
            check_assessment_access(assessment, "mallory", is_admin=False)


class TestFailureSemantics:
    def test_case_a_create_assessment_failure_leaves_the_occurrence_safely_retryable(
        self, session_factory
    ) -> None:
        schedule = _make_schedule(session_factory)
        occurrences = SqlAlchemyScheduleOccurrenceRepository(session_factory)
        assessments = FakeAssessmentRepository()
        flaky_create = _RaisesOnceCreateAssessment(CreateAssessment(assessments))
        submit_assessment = SubmitAssessment(assessments, FakeScanner(), RecordingJobRunner())
        orchestrator = SubmitScheduledAssessment(occurrences, flaky_create, submit_assessment, assessments)

        flaky_create.failures_remaining = 1
        with pytest.raises(RuntimeError, match="Case A"):
            orchestrator.execute(schedule)

        assert len(assessments.saved) == 0, "no assessment must exist after CreateAssessment fails"

        # Retry: the same occurrence, no duplicate creation attempt lost.
        result = orchestrator.execute(schedule)
        assert result.outcome == ScheduledAssessmentOutcome.SUBMITTED
        assert len(assessments.list()) == 1, "exactly one real assessment must exist after the successful retry"

    def test_case_b_submit_assessment_failure_resumes_without_creating_a_second_assessment(
        self, session_factory
    ) -> None:
        schedule = _make_schedule(session_factory)
        occurrences = SqlAlchemyScheduleOccurrenceRepository(session_factory)
        assessments = FakeAssessmentRepository()
        create_assessment = CreateAssessment(assessments)
        flaky_submit = _RaisesOnceSubmitAssessment(SubmitAssessment(assessments, FakeScanner(), RecordingJobRunner()))
        orchestrator = SubmitScheduledAssessment(occurrences, create_assessment, flaky_submit, assessments)

        flaky_submit.failures_remaining = 1
        with pytest.raises(RuntimeError, match="Case B"):
            orchestrator.execute(schedule)

        assert len(assessments.list()) == 1, "CreateAssessment must have succeeded before the injected submit failure"
        first_id = str(assessments.list()[0].id)

        # Retry: must resume submission on the SAME assessment, never call
        # CreateAssessment again.
        result = orchestrator.execute(schedule)
        assert result.outcome == ScheduledAssessmentOutcome.SUBMITTED
        assert result.assessment_id == first_id
        assert len(assessments.list()) == 1, "no second assessment must have been created"

    def test_case_e_the_same_occurrence_invoked_twice_after_success_takes_no_further_action(
        self, session_factory
    ) -> None:
        schedule = _make_schedule(session_factory)
        orchestrator, assessments = _build_orchestrator(session_factory)

        first = orchestrator.execute(schedule)
        assert first.outcome == ScheduledAssessmentOutcome.SUBMITTED
        assert len(assessments.list()) == 1

        second = orchestrator.execute(schedule)
        assert second.outcome == ScheduledAssessmentOutcome.NO_ACTION_TAKEN
        assert second.assessment_id == first.assessment_id
        assert len(assessments.list()) == 1, "the second invocation must not create a duplicate assessment"


def _fake_schedule(next_run: str | None) -> ScanSchedule:
    from kingsec.domain.schedule import RetryPolicy, ScheduleId, ScheduleStatus, ScheduleType

    return ScanSchedule(
        id=ScheduleId(str(uuid.uuid4())),
        name="Fake",
        description="",
        owner_user_id="alice",
        target="10.0.0.1",
        scanner_ids=(),
        config={},
        schedule_type=ScheduleType.CRON,
        cron_expression="0 2 * * *",
        timezone="UTC",
        enabled=True,
        paused=False,
        created_at="2026-09-01T00:00:00",
        updated_at="2026-09-01T00:00:00",
        last_run=None,
        next_run=next_run,
        retry_policy=RetryPolicy(),
        current_retry_count=0,
        status=ScheduleStatus.ACTIVE,
        version=1,
    )
