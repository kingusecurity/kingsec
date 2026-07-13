"""Tests for SubmitAssessment — background execution use case."""

from __future__ import annotations

import threading
import time
from collections.abc import Sequence
from datetime import datetime, timezone
from typing import Any
from unittest.mock import MagicMock

import pytest

from kingsec.application.dto import SubmitAssessmentRequest, SubmitAssessmentResponse
from kingsec.application.errors import AssessmentNotFoundError
from kingsec.application.job import JobId
from kingsec.application.ports.outbound.job_runner import JobRunner
from kingsec.application.submit_assessment import SubmitAssessment
from kingsec.domain import Assessment, AssessmentId, Finding, Severity, Target, TargetType
from kingsec.domain.authorization import Authorization
from kingsec.domain.enums import AssessmentStatus
from kingsec.domain.errors import IllegalStateTransition
from kingsec.domain.evidence import Recommendation


# --- Fakes and Stubs --------------------------------------------------------


class FakeAssessmentRepository:
    """In-memory repository for testing."""

    def __init__(self, assessments: dict[str, Assessment] | None = None) -> None:
        self._assessments = assessments or {}
        self._saved: list[Assessment] = []

    def get(self, assessment_id: AssessmentId) -> Assessment:
        a = self._assessments.get(str(assessment_id))
        if a is None:
            raise AssessmentNotFoundError(str(assessment_id))
        return a

    def save(self, assessment: Assessment) -> None:
        self._assessments[str(assessment.id)] = assessment
        self._saved.append(assessment)

    def list(self, *, limit: int = 50, offset: int = 0) -> list[Assessment]:
        ordered = sorted(self._assessments.values(), key=lambda a: a.created_at, reverse=True)
        return ordered[offset : offset + limit]

    def delete(self, assessment_id: AssessmentId) -> None:
        if str(assessment_id) not in self._assessments:
            raise AssessmentNotFoundError(str(assessment_id))
        del self._assessments[str(assessment_id)]

    @property
    def saved(self) -> list[Assessment]:
        return list(self._saved)


class FakeScanner:
    """Scanner that returns a fixed set of findings."""

    def __init__(self, findings: list[Finding] | None = None) -> None:
        self._findings = findings or []

    def scan(self, target: Any) -> Sequence[Finding]:
        return list(self._findings)


class RecordingJobRunner:
    """JobRunner that records submitted jobs and runs them inline (synchronously)."""

    def __init__(self, run_inline: bool = True) -> None:
        self._jobs: dict[str, Any] = {}
        self._run_inline = run_inline
        self._lock = threading.Lock()

    def submit(
        self,
        job_id: str,
        fn: Any,
        *args: Any,
        **kwargs: Any,
    ) -> None:
        with self._lock:
            self._jobs[job_id] = fn
        if self._run_inline:
            fn()

    def is_running(self, job_id: str) -> bool:
        with self._lock:
            return job_id in self._jobs

    def shutdown(self, wait: bool = True) -> None:
        pass


class FakeAI:
    """AI that returns a fixed recommendation."""

    def recommend(self, finding: Finding) -> Recommendation:
        return Recommendation(
            title=f"Fix {finding.title}",
            description=f"AI recommendation for {finding.title}",
            priority=finding.severity,
        )


# --- Helpers -----------------------------------------------------------------


def _make_assessment(
    *,
    assessment_id: str = "asmt-test-001",
    target: str = "10.0.0.5",
    status: AssessmentStatus = AssessmentStatus.AUTHORIZED,
) -> Assessment:
    """Build an Assessment in the desired state."""
    a = Assessment(assessment_id=AssessmentId(assessment_id), target=Target(target, TargetType.IP_ADDRESS))
    if status == AssessmentStatus.AUTHORIZED:
        a.authorize(Authorization("test-user", datetime.now(timezone.utc), scope="test-scope"))
    elif status == AssessmentStatus.RUNNING:
        a.authorize(Authorization("test-user", datetime.now(timezone.utc), scope="test-scope"))
        a.start()
    elif status == AssessmentStatus.COMPLETED:
        a.authorize(Authorization("test-user", datetime.now(timezone.utc), scope="test-scope"))
        a.start()
        a.complete()
    return a


# --- Tests -------------------------------------------------------------------


class TestSubmitAssessmentHappyPath:
    def test_transitions_to_running_and_submits_job(self) -> None:
        assessment = _make_assessment()
        repo = FakeAssessmentRepository({str(assessment.id): assessment})
        scanner = FakeScanner()
        job_runner = RecordingJobRunner(run_inline=True)
        ai = FakeAI()

        use_case = SubmitAssessment(
            assessments=repo,
            scanner=scanner,
            job_runner=job_runner,
            ai=ai,
        )

        request = SubmitAssessmentRequest(assessment_id="asmt-test-001")
        response = use_case.execute(request)

        assert isinstance(response, SubmitAssessmentResponse)
        assert response.assessment_id == "asmt-test-001"
        # With run_inline=True, the scan completes before the response is returned.
        assert response.status == "completed"
        assert response.job_id == "asmt-test-001"
        assert "asmt-test-001" in job_runner._jobs

    def test_assessment_saved_after_start(self) -> None:
        assessment = _make_assessment()
        repo = FakeAssessmentRepository({str(assessment.id): assessment})
        job_runner = RecordingJobRunner(run_inline=True)

        use_case = SubmitAssessment(
            assessments=repo,
            scanner=FakeScanner(),
            job_runner=job_runner,
        )

        use_case.execute(SubmitAssessmentRequest(assessment_id="asmt-test-001"))

        # Save called twice: once for start transition, once for complete.
        # With run_inline=True, the scan completes synchronously.
        assert len(repo.saved) == 2
        assert repo.saved[0].status == AssessmentStatus.COMPLETED
        assert repo.saved[1].status == AssessmentStatus.COMPLETED


class TestSubmitAssessmentAuthorizationGate:
    def test_draft_assessment_raises(self) -> None:
        assessment = _make_assessment(status=AssessmentStatus.DRAFT)
        repo = FakeAssessmentRepository({str(assessment.id): assessment})
        job_runner = RecordingJobRunner()

        use_case = SubmitAssessment(
            assessments=repo,
            scanner=FakeScanner(),
            job_runner=job_runner,
        )

        with pytest.raises(IllegalStateTransition):
            use_case.execute(SubmitAssessmentRequest(assessment_id="asmt-test-001"))

        # Job should not have been submitted
        assert "asmt-test-001" not in job_runner._jobs


class TestSubmitAssessmentWithAI:
    def test_findings_enriched_by_ai(self) -> None:
        finding = Finding.create(
            title="SQL Injection",
            description="Found SQL injection in login form",
            severity=Severity.CRITICAL,
        )
        assessment = _make_assessment()
        repo = FakeAssessmentRepository({str(assessment.id): assessment})
        scanner = FakeScanner(findings=[finding])
        job_runner = RecordingJobRunner(run_inline=True)
        ai = FakeAI()

        use_case = SubmitAssessment(
            assessments=repo,
            scanner=scanner,
            job_runner=job_runner,
            ai=ai,
        )

        use_case.execute(SubmitAssessmentRequest(assessment_id="asmt-test-001"))

        # The saved assessment (after scan) should have enriched findings
        completed = repo.saved[-1]
        assert len(completed.findings) == 1
        assert len(completed.findings[0].recommendations) == 1
        assert completed.findings[0].recommendations[0].title == "Fix SQL Injection"


class TestSubmitAssessmentScanFailure:
    def test_scan_error_marks_assessment_failed(self) -> None:
        """When the scanner raises, the assessment should be marked FAILED."""

        class _FailingScanner:
            def scan(self, target: Any) -> Sequence[Finding]:
                raise ConnectionError("scanner unreachable")

        assessment = _make_assessment()
        repo = FakeAssessmentRepository({str(assessment.id): assessment})
        job_runner = RecordingJobRunner(run_inline=True)

        use_case = SubmitAssessment(
            assessments=repo,
            scanner=_FailingScanner(),
            job_runner=job_runner,
        )

        use_case.execute(SubmitAssessmentRequest(assessment_id="asmt-test-001"))

        # Assessment should be FAILED after scanner error
        failed = repo.saved[-1]
        assert failed.status == AssessmentStatus.FAILED


class TestSubmitAssessmentNotFound:
    def test_nonexistent_assessment_raises(self) -> None:
        repo = FakeAssessmentRepository()
        job_runner = RecordingJobRunner()

        use_case = SubmitAssessment(
            assessments=repo,
            scanner=FakeScanner(),
            job_runner=job_runner,
        )

        with pytest.raises(AssessmentNotFoundError):
            use_case.execute(SubmitAssessmentRequest(assessment_id="asmt-nonexistent"))


class TestSubmitAssessmentBackgroundExecution:
    def test_job_runs_in_background_thread(self) -> None:
        """Verify the job actually runs in a separate thread."""
        thread_ids: list[int] = []

        assessment = _make_assessment()
        repo = FakeAssessmentRepository({str(assessment.id): assessment})
        scanner = FakeScanner()

        # Use a job runner that records which thread runs the job
        class _ThreadRecorderRunner:
            def __init__(self) -> None:
                self._jobs: dict[str, Any] = {}
                self._event = threading.Event()

            def submit(self, job_id: str, fn: Any, *args: Any, **kwargs: Any) -> None:
                def _wrapper() -> None:
                    thread_ids.append(threading.current_thread().ident or 0)
                    fn()
                    self._event.set()

                self._jobs[job_id] = _wrapper
                t = threading.Thread(target=_wrapper)
                t.start()

            def is_running(self, job_id: str) -> bool:
                return job_id in self._jobs

            def shutdown(self, wait: bool = True) -> None:
                pass

        job_runner = _ThreadRecorderRunner()

        use_case = SubmitAssessment(
            assessments=repo,
            scanner=scanner,
            job_runner=job_runner,
        )

        main_thread_id = threading.current_thread().ident or 0
        use_case.execute(SubmitAssessmentRequest(assessment_id="asmt-test-001"))

        # Wait for background job to complete
        job_runner._event.wait(timeout=2.0)

        assert len(thread_ids) == 1
        assert thread_ids[0] != main_thread_id
