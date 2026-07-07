"""Unit tests for the domain reconstitution factories.

These factories are the additive domain change that lets persistence rebuild an
aggregate in any stored state without replaying the lifecycle.
"""

from __future__ import annotations

import pytest

from kingsec.domain import (
    Assessment,
    AssessmentId,
    AssessmentStatus,
    Evidence,
    Finding,
    FindingId,
    FindingStatus,
    InvariantViolation,
    Severity,
    Target,
    TargetType,
)
from tests.unit.infrastructure.persistence.conftest import utc


class TestFindingReconstitute:
    def test_restores_closed_finding_with_evidence(self) -> None:
        finding = Finding.reconstitute(
            finding_id=FindingId("find-1"),
            title="XSS",
            description="reflected",
            severity=Severity.HIGH,
            status=FindingStatus.REMEDIATED,
            discovered_at=utc(),
            evidence=[Evidence("s", "d", utc())],
        )
        # A REMEDIATED finding with evidence — impossible to build via the normal
        # lifecycle (evidence can't be added after closing), proving reconstitute
        # sets state directly.
        assert finding.status is FindingStatus.REMEDIATED
        assert len(finding.evidence) == 1

    def test_still_enforces_structural_invariants(self) -> None:
        with pytest.raises(InvariantViolation):
            Finding.reconstitute(
                finding_id=FindingId("find-2"),
                title="",  # invalid
                description="d",
                severity=Severity.LOW,
                status=FindingStatus.OPEN,
                discovered_at=utc(),
            )


class TestAssessmentReconstitute:
    def test_restores_terminal_state_directly(self) -> None:
        assessment = Assessment.reconstitute(
            assessment_id=AssessmentId("asmt-1"),
            target=Target("h", TargetType.HOSTNAME),
            status=AssessmentStatus.CANCELLED,
            created_at=utc(),
            authorization=None,
            failure_reason=None,
        )
        assert assessment.status is AssessmentStatus.CANCELLED

    def test_rejects_duplicate_finding_ids(self) -> None:
        f1 = Finding.reconstitute(
            finding_id=FindingId("dup"),
            title="a",
            description="d",
            severity=Severity.LOW,
            status=FindingStatus.OPEN,
            discovered_at=utc(),
        )
        f2 = Finding.reconstitute(
            finding_id=FindingId("dup"),
            title="b",
            description="d",
            severity=Severity.LOW,
            status=FindingStatus.OPEN,
            discovered_at=utc(),
        )
        with pytest.raises(InvariantViolation, match="duplicate finding id"):
            Assessment.reconstitute(
                assessment_id=AssessmentId("asmt-2"),
                target=Target("h", TargetType.HOSTNAME),
                status=AssessmentStatus.RUNNING,
                created_at=utc(),
                authorization=None,
                failure_reason=None,
                findings=[f1, f2],
            )
