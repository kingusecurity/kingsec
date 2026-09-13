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
from kingsec.domain.enums import ScannerRunState


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
            selected_scanners=(PlanScannerEntry(scanner_id="nmap", name="Nmap", selected=True),),
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
                    scanner_id="nmap",
                    name="Nmap",
                    selected=False,
                    skip_state=ScannerRunState.SKIPPED_BINARY_MISSING,
                    reason="'Nmap' is not installed",
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


class _FakeConcurrencyPort:
    """In-memory stand-in for AssessmentConcurrencyPort - the real atomic-
    UPDATE-based implementation is tested with genuine concurrent threads
    against a real database in test_assessment_concurrency.py; this fake
    exists only to prove StartAssessment calls try_reserve_slot()/
    release_slot() at the right moments and the right number of times."""

    def __init__(self) -> None:
        self.reserved = 0
        self.release_calls = 0
        self.reserve_calls = 0

    def try_reserve_slot(self, max_concurrent: int) -> bool:
        self.reserve_calls += 1
        if self.reserved >= max_concurrent:
            return False
        self.reserved += 1
        return True

    def release_slot(self) -> None:
        self.release_calls += 1
        self.reserved = max(0, self.reserved - 1)


class _FailingScanner:
    """Raises during scan() - drives StartAssessment's own failure path
    (assessment.fail(), not an unhandled exception)."""

    def scan(self, target: Any, scanner_ids: Sequence[str] | None = None) -> Sequence[Finding]:
        raise RuntimeError("scanner crashed")

    def compatible_scanners(self, target: Any) -> dict[str, str]:
        return {}


class TestConcurrencyGate:
    """KSEC-87-02: StartAssessment's concurrency gate is only active when
    BOTH concurrency and max_concurrent are supplied - every test above
    this class constructs StartAssessment without them and must keep
    working unchanged (confirmed: the whole file above passes with zero
    modifications). These test the gate itself via a fake port; the real
    atomic-reservation mechanism's own concurrency-safety is proven
    separately against a real database in test_assessment_concurrency.py."""

    def test_a_reserved_slot_is_released_after_successful_completion(
        self, assessments: InMemoryAssessmentRepository
    ) -> None:
        assessment = _authorized(assessments)
        concurrency = _FakeConcurrencyPort()
        use_case = StartAssessment(
            assessments, StubScanner(make_findings()), concurrency=concurrency, max_concurrent=2
        )

        response = use_case.execute(StartAssessmentRequest(str(assessment.id)))

        assert response.status == AssessmentStatus.COMPLETED.value
        assert concurrency.reserve_calls == 1
        assert concurrency.release_calls == 1
        assert concurrency.reserved == 0, "the slot must not still be held after a successful run"

    def test_a_reserved_slot_is_released_after_the_scan_fails(
        self, assessments: InMemoryAssessmentRepository
    ) -> None:
        """Failure path: a failed assessment must not permanently consume
        a slot."""
        assessment = _authorized(assessments)
        concurrency = _FakeConcurrencyPort()
        use_case = StartAssessment(assessments, _FailingScanner(), concurrency=concurrency, max_concurrent=2)

        with pytest.raises(RuntimeError, match="scanner crashed"):
            use_case.execute(StartAssessmentRequest(str(assessment.id)))

        assert concurrency.release_calls == 1
        assert concurrency.reserved == 0
        stored = assessments.get(assessment.id)
        assert stored.status == AssessmentStatus.FAILED

    def test_a_reserved_slot_is_released_even_if_startup_itself_fails(
        self, assessments: InMemoryAssessmentRepository
    ) -> None:
        """Transaction-rollback requirement: if the reservation succeeds
        but something fails before scanning even begins (here, the
        domain's own authorization gate rejecting an unauthorized
        assessment), the reservation must not leak."""
        assessment = _draft(assessments)  # never authorized
        concurrency = _FakeConcurrencyPort()
        use_case = StartAssessment(assessments, StubScanner([]), concurrency=concurrency, max_concurrent=2)

        with pytest.raises(IllegalStateTransition):
            use_case.execute(StartAssessmentRequest(str(assessment.id)))

        assert concurrency.release_calls == 1
        assert concurrency.reserved == 0

    def test_capacity_exhausted_rejects_without_ever_scanning(
        self, assessments: InMemoryAssessmentRepository
    ) -> None:
        from kingsec.application.errors import TooManyConcurrentAssessmentsError

        assessment = _authorized(assessments)
        concurrency = _FakeConcurrencyPort()
        concurrency.reserved = 2  # already at the configured limit
        scanner = _RecordingScanner(make_findings())
        use_case = StartAssessment(assessments, scanner, concurrency=concurrency, max_concurrent=2)

        with pytest.raises(TooManyConcurrentAssessmentsError):
            use_case.execute(StartAssessmentRequest(str(assessment.id)))

        assert scanner.scan_calls == [], "capacity must be checked before any scanning work begins"
        assert concurrency.release_calls == 0, "a rejected reservation was never claimed - nothing to release"
        stored = assessments.get(assessment.id)
        assert stored.status == AssessmentStatus.AUTHORIZED, "a rejected reservation must not mutate the assessment"

    def test_the_gate_is_skipped_entirely_when_not_configured(
        self, assessments: InMemoryAssessmentRepository
    ) -> None:
        """Matches every other test in this file: concurrency=None,
        max_concurrent=None (the defaults) must behave exactly as before
        this feature existed - no gate, no reservation, no release."""
        assessment = _authorized(assessments)
        use_case = StartAssessment(assessments, StubScanner(make_findings()))

        response = use_case.execute(StartAssessmentRequest(str(assessment.id)))

        assert response.status == AssessmentStatus.COMPLETED.value
