"""Tests for SubmitAssessment — background execution use case."""

from __future__ import annotations

import threading
from collections.abc import Sequence
from datetime import UTC, datetime
from typing import Any

import pytest

from kingsec.application.assessment_execution import AssessmentExecutionEngine
from kingsec.application.assessment_profiles import ExecutionPlan, PlanScannerEntry
from kingsec.application.dto import SubmitAssessmentRequest, SubmitAssessmentResponse
from kingsec.application.errors import AssessmentNotFoundError
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

    def compatible_scanners(self, target: Any) -> dict[str, str]:
        return {"fake": "Fake Scanner"}


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


class RecordingScanner:
    """Scanner that records the scanner_ids it was called with."""

    def __init__(self, findings: list[Finding] | None = None) -> None:
        self._findings = findings or []
        self.scan_calls: list[Sequence[str] | None] = []

    def scan(self, target: Any, scanner_ids: Sequence[str] | None = None) -> Sequence[Finding]:
        self.scan_calls.append(scanner_ids)
        return list(self._findings)

    def compatible_scanners(self, target: Any) -> dict[str, str]:
        return {"nmap": "Nmap", "nuclei": "Nuclei"}


class _ScriptedPlanner:
    """Stub ExecutionPlanner returning a scripted plan regardless of input."""

    def __init__(self, plan: ExecutionPlan) -> None:
        self._plan = plan

    def plan(self, profile_id: str, target_value: str, target_type: Any) -> ExecutionPlan:
        return self._plan


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
    profile_id: str | None = None,
) -> Assessment:
    """Build an Assessment in the desired state."""
    a = Assessment(
        assessment_id=AssessmentId(assessment_id),
        target=Target(target, TargetType.IP_ADDRESS),
        profile_id=profile_id,
    )
    if status == AssessmentStatus.AUTHORIZED:
        a.authorize(Authorization("test-user", datetime.now(UTC), scope="test-scope"))
    elif status == AssessmentStatus.RUNNING:
        a.authorize(Authorization("test-user", datetime.now(UTC), scope="test-scope"))
        a.start()
    elif status == AssessmentStatus.COMPLETED:
        a.authorize(Authorization("test-user", datetime.now(UTC), scope="test-scope"))
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

        request = SubmitAssessmentRequest(assessment_id="asmt-test-001", is_admin=True)
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

        use_case.execute(SubmitAssessmentRequest(assessment_id="asmt-test-001", is_admin=True))

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
            use_case.execute(SubmitAssessmentRequest(assessment_id="asmt-test-001", is_admin=True))

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

        use_case.execute(SubmitAssessmentRequest(assessment_id="asmt-test-001", is_admin=True))

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

            def compatible_scanners(self, target: Any) -> dict[str, str]:
                return {"failing": "Failing Scanner"}

        assessment = _make_assessment()
        repo = FakeAssessmentRepository({str(assessment.id): assessment})
        job_runner = RecordingJobRunner(run_inline=True)

        use_case = SubmitAssessment(
            assessments=repo,
            scanner=_FailingScanner(),
            job_runner=job_runner,
        )

        use_case.execute(SubmitAssessmentRequest(assessment_id="asmt-test-001", is_admin=True))

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
            use_case.execute(SubmitAssessmentRequest(assessment_id="asmt-nonexistent", is_admin=True))


class TestSubmitAssessmentAccessControl:
    def test_non_owner_gets_not_found(self) -> None:
        assessment = _make_assessment()
        assessment.set_ownership("alice")
        repo = FakeAssessmentRepository({str(assessment.id): assessment})
        job_runner = RecordingJobRunner()

        use_case = SubmitAssessment(
            assessments=repo,
            scanner=FakeScanner(),
            job_runner=job_runner,
        )

        with pytest.raises(AssessmentNotFoundError):
            use_case.execute(
                SubmitAssessmentRequest(
                    assessment_id="asmt-test-001", requesting_user="bob", is_admin=False
                )
            )
        assert "asmt-test-001" not in job_runner._jobs

    def test_owner_can_submit(self) -> None:
        assessment = _make_assessment()
        assessment.set_ownership("alice")
        repo = FakeAssessmentRepository({str(assessment.id): assessment})
        job_runner = RecordingJobRunner(run_inline=True)

        use_case = SubmitAssessment(
            assessments=repo,
            scanner=FakeScanner(),
            job_runner=job_runner,
        )

        response = use_case.execute(
            SubmitAssessmentRequest(
                assessment_id="asmt-test-001", requesting_user="alice", is_admin=False
            )
        )
        assert response.status == "completed"


class TestSubmitAssessmentExecutionEngineWiring:
    """Regression coverage for the bug where _execute_scan() passed a
    hardcoded empty dict to start_execution() instead of the scanner's
    real compatible_scanners() mapping - so ExecutionProgressPanel always
    rendered zero scanner rows for a real run, even though the scan had
    genuinely run and completed."""

    def test_start_execution_receives_real_scanner_mapping(self) -> None:
        assessment = _make_assessment()
        repo = FakeAssessmentRepository({str(assessment.id): assessment})
        scanner = FakeScanner()
        job_runner = RecordingJobRunner(run_inline=True)
        engine = AssessmentExecutionEngine()

        use_case = SubmitAssessment(
            assessments=repo,
            scanner=scanner,
            job_runner=job_runner,
            execution_engine=engine,
        )

        use_case.execute(SubmitAssessmentRequest(assessment_id="asmt-test-001", is_admin=True))

        state = engine.get_state("asmt-test-001")
        assert state is not None
        # Not empty - this is the actual bug: it used to be start_execution(id, {}).
        assert len(state.scanner_progress) == 1
        assert state.scanner_progress[0].scanner_id == "fake"
        assert state.scanner_progress[0].name == "Fake Scanner"

    def test_scanner_mapping_reflects_compatible_scanners_not_a_guess(self) -> None:
        """A scanner reporting multiple compatible scanners (the real
        ScannerOrchestrator can) must show up as multiple tracked entries,
        not just one - proving the mapping is genuinely threaded through,
        not a single hardcoded placeholder swapped in for another."""

        class MultiScanner:
            def scan(self, target: Any) -> Sequence[Finding]:
                return []

            def compatible_scanners(self, target: Any) -> dict[str, str]:
                return {"nmap": "Nmap", "nuclei": "Nuclei"}

        assessment = _make_assessment()
        repo = FakeAssessmentRepository({str(assessment.id): assessment})
        job_runner = RecordingJobRunner(run_inline=True)
        engine = AssessmentExecutionEngine()

        use_case = SubmitAssessment(
            assessments=repo,
            scanner=MultiScanner(),
            job_runner=job_runner,
            execution_engine=engine,
        )

        use_case.execute(SubmitAssessmentRequest(assessment_id="asmt-test-001", is_admin=True))

        state = engine.get_state("asmt-test-001")
        assert state is not None
        tracked_ids = {sp.scanner_id for sp in state.scanner_progress}
        assert tracked_ids == {"nmap", "nuclei"}

    def test_execution_state_exists_before_background_job_runs(self) -> None:
        """Regression test for a race that produced real, user-visible
        "Failed to load execution status" errors: the client starts
        polling GET .../execution/status as soon as it sees the submit
        response, but the background job (which used to be the only
        place calling start_execution()) isn't guaranteed to have been
        scheduled by the thread pool yet. That poll used to 404 for an
        assessment that was, in fact, running and would go on to
        complete normally. Tracked state must exist synchronously, in
        the request thread, before the job is even submitted."""
        assessment = _make_assessment()
        repo = FakeAssessmentRepository({str(assessment.id): assessment})
        scanner = FakeScanner()
        job_runner = RecordingJobRunner(run_inline=False)
        engine = AssessmentExecutionEngine()

        use_case = SubmitAssessment(
            assessments=repo,
            scanner=scanner,
            job_runner=job_runner,
            execution_engine=engine,
        )

        use_case.execute(SubmitAssessmentRequest(assessment_id="asmt-test-001", is_admin=True))

        # The job was submitted but deliberately never run, simulating a
        # client poll that lands before the thread pool schedules it.
        state = engine.get_state("asmt-test-001")
        assert state is not None
        assert state.phase.value == "preparing"

    def test_phase_reaches_completed_with_real_mapping(self) -> None:
        assessment = _make_assessment()
        repo = FakeAssessmentRepository({str(assessment.id): assessment})
        job_runner = RecordingJobRunner(run_inline=True)
        engine = AssessmentExecutionEngine()

        use_case = SubmitAssessment(
            assessments=repo,
            scanner=FakeScanner(),
            job_runner=job_runner,
            execution_engine=engine,
        )

        use_case.execute(SubmitAssessmentRequest(assessment_id="asmt-test-001", is_admin=True))

        state = engine.get_state("asmt-test-001")
        assert state is not None
        assert state.phase.value == "completed"


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
        use_case.execute(SubmitAssessmentRequest(assessment_id="asmt-test-001", is_admin=True))

        # Wait for background job to complete
        job_runner._event.wait(timeout=2.0)

        assert len(thread_ids) == 1
        assert thread_ids[0] != main_thread_id


class TestSubmitAssessmentProfileGating:
    """Coverage for Part 2: profile_id gates which scanners actually run,
    and the plan is re-checked at execution time rather than trusted from
    an earlier client-side /plan preview."""

    def test_profile_id_none_scans_without_a_scanner_ids_filter(self) -> None:
        """Backward compatibility: no profile means today's exact
        'run everything compatible' behavior - scan() is called exactly
        as it always has been, with no scanner_ids argument at all."""
        assessment = _make_assessment()
        repo = FakeAssessmentRepository({str(assessment.id): assessment})
        scanner = RecordingScanner()
        job_runner = RecordingJobRunner(run_inline=True)

        use_case = SubmitAssessment(
            assessments=repo,
            scanner=scanner,
            job_runner=job_runner,
        )

        use_case.execute(SubmitAssessmentRequest(assessment_id="asmt-test-001", is_admin=True))

        assert scanner.scan_calls == [None]
        assert repo.saved[-1].status == AssessmentStatus.COMPLETED

    def test_plan_selected_scanners_are_passed_to_scan(self) -> None:
        """A profile's plan.selected_scanners (not its full static list)
        becomes the scanner_ids filter passed to scan()."""
        assessment = _make_assessment(profile_id="quick-scan")
        repo = FakeAssessmentRepository({str(assessment.id): assessment})
        scanner = RecordingScanner()
        job_runner = RecordingJobRunner(run_inline=True)
        plan = ExecutionPlan(
            profile_id="quick-scan",
            profile_name="Quick Host Scan",
            target_value="10.0.0.5",
            target_type=TargetType.IP_ADDRESS,
            selected_scanners=(PlanScannerEntry(scanner_id="nmap", name="Nmap", status="selected"),),
            skipped_scanners=(PlanScannerEntry(scanner_id="nuclei", name="Nuclei", status="skipped", reason="not selected"),),
            unavailable_scanners=(),
            warnings=(),
            estimated_duration_minutes=5,
            can_proceed=True,
        )

        use_case = SubmitAssessment(
            assessments=repo,
            scanner=scanner,
            job_runner=job_runner,
            planner=_ScriptedPlanner(plan),
        )

        use_case.execute(SubmitAssessmentRequest(assessment_id="asmt-test-001", is_admin=True))

        assert scanner.scan_calls == [("nmap",)]
        assert repo.saved[-1].status == AssessmentStatus.COMPLETED

    def test_required_scanner_unavailable_fails_cleanly_without_scanning(self) -> None:
        """Server-side re-validation: if the plan can't proceed at execution
        time, the assessment fails with a clear reason and scan() is never
        called - no silent subset run, no trusting stale client-side data."""
        assessment = _make_assessment(profile_id="quick-scan")
        repo = FakeAssessmentRepository({str(assessment.id): assessment})
        scanner = RecordingScanner()
        job_runner = RecordingJobRunner(run_inline=True)
        plan = ExecutionPlan(
            profile_id="quick-scan",
            profile_name="Quick Host Scan",
            target_value="10.0.0.5",
            target_type=TargetType.IP_ADDRESS,
            selected_scanners=(),
            skipped_scanners=(),
            unavailable_scanners=(
                PlanScannerEntry(
                    scanner_id="nmap", name="Nmap", status="required_unavailable", reason="'Nmap' is not installed"
                ),
            ),
            warnings=("Required scanner 'Nmap' is not installed.",),
            estimated_duration_minutes=0,
            can_proceed=False,
        )

        use_case = SubmitAssessment(
            assessments=repo,
            scanner=scanner,
            job_runner=job_runner,
            planner=_ScriptedPlanner(plan),
        )

        use_case.execute(SubmitAssessmentRequest(assessment_id="asmt-test-001", is_admin=True))

        assert scanner.scan_calls == []
        failed = repo.saved[-1]
        assert failed.status == AssessmentStatus.FAILED
        assert "not installed" in (failed.failure_reason or "")
