"""StartAssessment use case: gate, scanning, enrichment, resilience."""

from __future__ import annotations

from collections.abc import Sequence
from typing import Any

import pytest
from tests.unit.application.conftest import (
    FailingAI,
    InMemoryAssessmentRepository,
    StubAI,
    StubScanner,
    make_findings,
)

from kingsec.application import (
    AssessmentNotFoundError,
    StartAssessment,
    StartAssessmentRequest,
)
from kingsec.application.assessment_profiles import ExecutionPlan, PlanScannerEntry
from kingsec.domain import (
    Assessment,
    AssessmentStatus,
    Authorization,
    Finding,
    IllegalStateTransition,
    Severity,
    Target,
    TargetType,
)


def _authorized(assessments: InMemoryAssessmentRepository, profile_id: str | None = None) -> Assessment:
    assessment = Assessment.create(Target("10.0.0.5", TargetType.IP_ADDRESS), profile_id=profile_id)
    assessment.authorize(Authorization.grant("tester", scope="10.0.0.5"))
    assessments.save(assessment)
    return assessment


class _RecordingScanner:
    """Scanner that records the scanner_ids it was called with."""

    def __init__(self, findings: Sequence[Finding] | None = None) -> None:
        self._findings = list(findings or [])
        self.scan_calls: list[Sequence[str] | None] = []

    def scan(self, target: Any, scanner_ids: Sequence[str] | None = None) -> Sequence[Finding]:
        self.scan_calls.append(scanner_ids)
        return list(self._findings)

    def compatible_scanners(self, target: Any) -> dict[str, str]:
        return {"nmap": "Nmap"}


class _ScriptedPlanner:
    """Stub ExecutionPlanner returning a scripted plan regardless of input."""

    def __init__(self, plan: ExecutionPlan) -> None:
        self._plan = plan

    def plan(self, profile_id: str, target_value: str, target_type: Any) -> ExecutionPlan:
        return self._plan


def _draft(assessments: InMemoryAssessmentRepository) -> Assessment:
    assessment = Assessment.create(Target("10.0.0.5", TargetType.IP_ADDRESS))
    assessments.save(assessment)  # never authorized
    return assessment


class TestHappyPath:
    def test_runs_scan_records_findings_and_completes(self, assessments: InMemoryAssessmentRepository) -> None:
        assessment = _authorized(assessments)
        use_case = StartAssessment(assessments, StubScanner(make_findings()), StubAI())

        response = use_case.execute(StartAssessmentRequest(str(assessment.id)))

        assert response.status == AssessmentStatus.COMPLETED.value
        assert response.findings_count == 2
        assert response.highest_severity == Severity.CRITICAL.label

        stored = assessments.get(assessment.id)
        # AI enrichment attached a recommendation to each finding.
        assert all(f.recommendations for f in stored.findings)


class TestAuthorizationGate:
    def test_cannot_start_unauthorized_assessment(self, assessments: InMemoryAssessmentRepository) -> None:
        assessment = _draft(assessments)
        use_case = StartAssessment(assessments, StubScanner(make_findings()))

        # The domain gate fires and the use case lets it propagate.
        with pytest.raises(IllegalStateTransition):
            use_case.execute(StartAssessmentRequest(str(assessment.id)))


class TestErrors:
    def test_unknown_assessment_raises_not_found(self, assessments: InMemoryAssessmentRepository) -> None:
        use_case = StartAssessment(assessments, StubScanner([]))
        with pytest.raises(AssessmentNotFoundError):
            use_case.execute(StartAssessmentRequest("asmt-does-not-exist"))


class TestAiResilience:
    def test_ai_failure_does_not_fail_the_scan(self, assessments: InMemoryAssessmentRepository) -> None:
        assessment = _authorized(assessments)
        use_case = StartAssessment(assessments, StubScanner(make_findings()), FailingAI())

        response = use_case.execute(StartAssessmentRequest(str(assessment.id)))

        # Scan still completes; findings recorded, just without AI recommendations.
        assert response.status == AssessmentStatus.COMPLETED.value
        assert response.findings_count == 2
        stored = assessments.get(assessment.id)
        assert all(not f.recommendations for f in stored.findings)

    def test_runs_without_any_ai_port(self, assessments: InMemoryAssessmentRepository) -> None:
        assessment = _authorized(assessments)
        use_case = StartAssessment(assessments, StubScanner(make_findings()))  # ai=None
        response = use_case.execute(StartAssessmentRequest(str(assessment.id)))
        assert response.findings_count == 2


class TestProfileGating:
    """Coverage for Part 2: profile_id gates which scanners actually run,
    re-checked at execution time rather than trusted from an earlier plan."""

    def test_profile_id_none_scans_without_a_scanner_ids_filter(
        self, assessments: InMemoryAssessmentRepository
    ) -> None:
        assessment = _authorized(assessments)
        scanner = _RecordingScanner(make_findings())
        use_case = StartAssessment(assessments, scanner)

        response = use_case.execute(StartAssessmentRequest(str(assessment.id)))

        assert scanner.scan_calls == [None]
        assert response.status == AssessmentStatus.COMPLETED.value

    def test_plan_selected_scanners_are_passed_to_scan(self, assessments: InMemoryAssessmentRepository) -> None:
        assessment = _authorized(assessments, profile_id="quick-scan")
        scanner = _RecordingScanner(make_findings())
        plan = ExecutionPlan(
            profile_id="quick-scan",
            profile_name="Quick Host Scan",
            target_value="10.0.0.5",
            target_type=TargetType.IP_ADDRESS,
            selected_scanners=(PlanScannerEntry(scanner_id="nmap", name="Nmap", status="selected"),),
            skipped_scanners=(),
            unavailable_scanners=(),
            warnings=(),
            estimated_duration_minutes=5,
            can_proceed=True,
        )
        use_case = StartAssessment(assessments, scanner, planner=_ScriptedPlanner(plan))

        response = use_case.execute(StartAssessmentRequest(str(assessment.id)))

        assert scanner.scan_calls == [("nmap",)]
        assert response.status == AssessmentStatus.COMPLETED.value

    def test_required_scanner_unavailable_fails_cleanly_without_scanning(
        self, assessments: InMemoryAssessmentRepository
    ) -> None:
        assessment = _authorized(assessments, profile_id="quick-scan")
        scanner = _RecordingScanner(make_findings())
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
        use_case = StartAssessment(assessments, scanner, planner=_ScriptedPlanner(plan))

        with pytest.raises(Exception, match="not installed"):
            use_case.execute(StartAssessmentRequest(str(assessment.id)))

        assert scanner.scan_calls == []
        stored = assessments.get(assessment.id)
        assert stored.status == AssessmentStatus.FAILED
        assert "not installed" in (stored.failure_reason or "")
