"""Phase 06: reproduction + regression for the scanner-failure completion policy.

Per Phase 05's decision (Option A), only one row of the policy table changes:
"all attempted scanners failed" must transition the assessment to FAILED with
a scanner-name-based reason, instead of the current unconditional COMPLETED.
Every other row (all succeeded, some failed/some succeeded, all pre-planned
skips, empty attempted-set) must stay exactly as it is today.

These tests exercise the REAL production wiring shape: a real
ScannerOrchestrator + InMemoryPluginRegistry (implementing both ScannerPort
and ScannerExecutor, exactly as bootstrap/composition.py's
_resolve_scanner_executor() binds them), a real AssessmentExecutionEngine,
and the real SubmitAssessment use case - this is Path A from Phase 06 §2.1's
control-flow trace (scanner_executor is not None), the only path this fix
touches and the only path real production traffic ever takes.

Written FIRST, before any fix, per Phase 06's ground rule #3. Run against
unmodified code, they fail because submit_assessment.py's assessment.complete()
call is unconditional.
"""

from __future__ import annotations

from typing import Any

from kingsec.application.assessment_execution import AssessmentExecutionEngine
from kingsec.application.assessment_profiles import ExecutionPlan, PlanScannerEntry
from kingsec.application.dto import SubmitAssessmentRequest
from kingsec.application.submit_assessment import SubmitAssessment
from kingsec.domain import (
    Assessment,
    Authorization,
    Finding,
    OutputFormat,
    PluginAvailability,
    PluginConfig,
    ScanCategory,
    ScannerCapability,
    ScannerId,
    ScannerPluginMetadata,
    ScannerRequirement,
    ScannerResult,
    ScannerSurfaceTier,
    Severity,
    Target,
    TargetType,
)
from kingsec.domain.enums import AssessmentStatus, ScannerRunState
from kingsec.infrastructure.scanner.orchestrator import ScannerOrchestrator
from kingsec.infrastructure.scanner.registry import InMemoryPluginRegistry


class _StubPlugin:
    """Configurable fake ScannerPluginPort - same shape as
    test_orchestrator.py's own _StubPlugin, reproduced locally so this file
    stays self-contained rather than importing another test module's
    private helpers."""

    def __init__(
        self,
        *,
        plugin_id: str,
        findings: tuple[Finding, ...] = (),
        raise_on_scan: Exception | None = None,
    ) -> None:
        self._id = plugin_id
        self._findings = findings
        self._raise_on_scan = raise_on_scan

    def metadata(self) -> ScannerPluginMetadata:
        return ScannerPluginMetadata(
            id=ScannerId(self._id),
            name=f"{self._id.title()} Scanner",
            version="1.0.0",
            author="Test",
            description=f"Stub plugin {self._id}",
            api_version="1.0",
        )

    def capabilities(self) -> tuple[ScannerCapability, ...]:
        return (
            ScannerCapability(
                requirement=ScannerRequirement.REACHABLE_HOST,
                scan_categories=frozenset({ScanCategory.VULNERABILITY}),
                output_format=OutputFormat.FINDINGS,
                surface_tier=ScannerSurfaceTier.HOST_PORT_PATH,
            ),
        )

    def is_available(self) -> PluginAvailability:
        return PluginAvailability(available=True)

    def scan(self, target: Target, config: PluginConfig) -> ScannerResult:
        if self._raise_on_scan is not None:
            raise self._raise_on_scan
        return ScannerResult(
            scanner_id=ScannerId(self._id),
            findings=self._findings,
            raw_output="",
            duration_seconds=0.05,
        )

    def health_check(self) -> None:
        pass

    def shutdown(self) -> None:
        pass


class InMemoryAssessmentRepository:
    def __init__(self) -> None:
        self._store: dict[str, Assessment] = {}

    def save(self, assessment: Assessment) -> None:
        self._store[assessment.id.value] = assessment

    def get(self, assessment_id: Any) -> Assessment:
        return self._store[assessment_id.value]

    def list(self, *, limit: int = 50, offset: int = 0) -> list[Assessment]:
        return list(self._store.values())[offset : offset + limit]

    def delete(self, assessment_id: Any) -> None:
        del self._store[assessment_id.value]


class _InlineJobRunner:
    """Runs the submitted job synchronously, in-thread - deterministic for tests."""

    def submit(self, job_id: str, fn: Any, *args: Any, **kwargs: Any) -> None:
        fn()

    def is_running(self, job_id: str) -> bool:
        return False

    def shutdown(self, wait: bool = True) -> None:
        pass


class _ScriptedPlanner:
    """Stub ExecutionPlanner returning a scripted plan regardless of input."""

    def __init__(self, plan: ExecutionPlan) -> None:
        self._plan = plan

    def plan(self, profile_id: str, target_value: str, target_type: Any) -> ExecutionPlan:
        return self._plan


def _finding(title: str = "Open port 22/tcp") -> Finding:
    return Finding.create(title, "desc", Severity.LOW)


def _run(plugins: list[Any], *, planner: Any = None, profile_id: str | None = None) -> Assessment:
    """Wire the real production shape and submit one assessment through it."""
    registry = InMemoryPluginRegistry()
    for p in plugins:
        registry.register(p)
    orchestrator = ScannerOrchestrator(registry)

    repo = InMemoryAssessmentRepository()
    engine = AssessmentExecutionEngine()

    assessment = Assessment.create(Target("10.0.0.5", TargetType.IP_ADDRESS), profile_id=profile_id)
    assessment.authorize(Authorization.grant("tester", scope="10.0.0.5"))
    assessment.set_ownership("alice")
    repo.save(assessment)

    use_case = SubmitAssessment(
        assessments=repo,
        scanner=orchestrator,
        job_runner=_InlineJobRunner(),
        execution_engine=engine,
        scanner_executor=orchestrator,
        planner=planner,
    )
    use_case.execute(SubmitAssessmentRequest(str(assessment.id), requesting_user="alice", is_admin=False))
    return repo.get(assessment.id)


class TestAllAttemptedScannersFailed:
    def test_all_failed_transitions_to_failed(self) -> None:
        result = _run(
            [
                _StubPlugin(plugin_id="nuclei", raise_on_scan=ConnectionError("refused")),
                _StubPlugin(plugin_id="nmap", raise_on_scan=ConnectionError("refused")),
            ]
        )
        assert result.status == AssessmentStatus.FAILED

    def test_all_failed_reason_names_the_scanners(self) -> None:
        result = _run(
            [
                _StubPlugin(plugin_id="nuclei", raise_on_scan=ConnectionError("refused")),
                _StubPlugin(plugin_id="nmap", raise_on_scan=ConnectionError("refused")),
            ]
        )
        assert result.failure_reason is not None
        assert "Nuclei" in result.failure_reason
        assert "Nmap" in result.failure_reason

    def test_all_failed_reason_contains_no_raw_exception_text(self) -> None:
        result = _run(
            [
                _StubPlugin(
                    plugin_id="nuclei",
                    raise_on_scan=ConnectionError("Connection refused: internal-scanner.corp.local:9200"),
                )
            ]
        )
        assert result.failure_reason is not None
        assert "internal-scanner.corp.local" not in result.failure_reason
        assert "9200" not in result.failure_reason
        assert "ConnectionError" not in result.failure_reason

    def test_single_scanner_failing_also_transitions_to_failed(self) -> None:
        result = _run([_StubPlugin(plugin_id="nuclei", raise_on_scan=RuntimeError("boom"))])
        assert result.status == AssessmentStatus.FAILED
        assert result.failure_reason is not None
        assert "Nuclei" in result.failure_reason


class TestPartialFailureStaysCompleted:
    # Phase 2A FIX 3 (already-decided, unchanged by this phase) introduced
    # a third status, COMPLETED_WITH_GAPS, for exactly this row: some
    # scanners succeeded, some didn't. This class predates that status
    # (Phase 06 only had COMPLETED/FAILED) - the assertions below reflect
    # the current, correct behavior, not the class name's original framing.
    def test_some_failed_some_succeeded_with_findings_stays_completed(self) -> None:
        result = _run(
            [
                _StubPlugin(plugin_id="nuclei", raise_on_scan=ConnectionError("refused")),
                _StubPlugin(plugin_id="nmap", findings=(_finding(),)),
            ]
        )
        assert result.status == AssessmentStatus.COMPLETED_WITH_GAPS
        assert result.failure_reason is None
        assert len(result.findings) == 1

    def test_some_failed_some_succeeded_zero_findings_stays_completed(self) -> None:
        # The row most likely to regress accidentally: findings-count-wise
        # this looks identical to "all failed" (zero findings either way),
        # but here one scanner genuinely ran and completed - it just found
        # nothing. Must NOT be mislabeled FAILED.
        result = _run(
            [
                _StubPlugin(plugin_id="nuclei", raise_on_scan=ConnectionError("refused")),
                _StubPlugin(plugin_id="nmap", findings=()),
            ]
        )
        assert result.status == AssessmentStatus.COMPLETED_WITH_GAPS
        assert result.failure_reason is None
        assert len(result.findings) == 0


class TestAllSucceededUnchanged:
    def test_all_succeeded_zero_findings_stays_completed(self) -> None:
        result = _run([_StubPlugin(plugin_id="nuclei", findings=())])
        assert result.status == AssessmentStatus.COMPLETED
        assert result.failure_reason is None

    def test_all_succeeded_with_findings_stays_completed(self) -> None:
        result = _run([_StubPlugin(plugin_id="nuclei", findings=(_finding(),))])
        assert result.status == AssessmentStatus.COMPLETED
        assert result.failure_reason is None


class TestEmptyAttemptedSetGuard:
    def test_no_compatible_plugins_stays_completed_not_failed(self) -> None:
        # No plugins registered at all -> execute_all() runs zero iterations
        # -> the attempted set is empty. Must not be treated as "all failed"
        # (vacuous truth) - this is the guard the prompt explicitly warns is
        # the most likely bug in this fix.
        result = _run([])
        assert result.status == AssessmentStatus.COMPLETED
        assert result.failure_reason is None


class TestAllPreplannedSkipsStayCompleted:
    def test_all_scanners_preplanned_skipped_stays_completed(self) -> None:
        # A profile whose plan deliberately selects nothing (e.g. every
        # compatible scanner excluded by profile policy). Phase 06 treated
        # this as "nothing attempted, so nothing failed -> COMPLETED", but
        # Phase 2A FIX 3 (already-decided, unchanged by this phase)
        # generalized "zero scanners succeeded" to FAILED regardless of
        # why - a report with literally zero collected evidence must never
        # present as an ordinary successful outcome, even when every
        # scanner was skipped rather than erroring.
        plan = ExecutionPlan(
            profile_id="quick-scan",
            profile_name="Quick Scan",
            target_value="10.0.0.5",
            target_type=TargetType.IP_ADDRESS,
            selected_scanners=(),
            skipped_scanners=(
                PlanScannerEntry(
                    scanner_id="nikto",
                    name="Nikto",
                    selected=False,
                    skip_state=ScannerRunState.SKIPPED_INCOMPATIBLE,
                    reason="excluded by profile",
                ),
            ),
            unavailable_scanners=(),
            warnings=(),
            estimated_duration_minutes=0,
            can_proceed=True,
        )
        result = _run(
            [_StubPlugin(plugin_id="nikto", findings=())],
            planner=_ScriptedPlanner(plan),
            profile_id="quick-scan",
        )
        assert result.status == AssessmentStatus.FAILED
        assert result.failure_reason is not None
        assert any(s.status.is_skip for s in result.scanner_summary)
