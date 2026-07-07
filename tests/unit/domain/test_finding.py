"""Finding entity: invariants, identity, evidence accrual, status transitions."""

from __future__ import annotations

import pytest

from kingsec.domain import (
    Evidence,
    Finding,
    FindingId,
    FindingStatus,
    IllegalStateTransition,
    InvariantViolation,
    Recommendation,
    Severity,
)
from tests.unit.domain.conftest import make_finding


class TestConstruction:
    def test_starts_open(self) -> None:
        assert make_finding().status is FindingStatus.OPEN

    def test_requires_non_empty_title(self) -> None:
        with pytest.raises(InvariantViolation):
            Finding.create("", "desc", Severity.LOW)

    def test_requires_severity_type(self) -> None:
        with pytest.raises(InvariantViolation):
            Finding(FindingId.generate(), "t", "d", "high")  # type: ignore[arg-type]


class TestIdentity:
    def test_equality_is_by_id_not_content(self) -> None:
        fid = FindingId.generate()
        a = Finding(fid, "Title A", "desc", Severity.LOW)
        b = Finding(fid, "Title B", "different", Severity.CRITICAL)
        assert a == b                 # same id -> same entity
        assert hash(a) == hash(b)

    def test_different_ids_are_not_equal(self) -> None:
        assert make_finding() != make_finding()


class TestEvidenceAccrual:
    def test_add_evidence_returns_immutable_view(self) -> None:
        finding = make_finding()
        finding.add_evidence(Evidence.create("resp", "500 error"))
        evidence = finding.evidence
        assert len(evidence) == 1
        assert isinstance(evidence, tuple)   # callers cannot mutate internals

    def test_cannot_add_evidence_once_closed(self) -> None:
        finding = make_finding()
        finding.mark_false_positive()
        with pytest.raises(IllegalStateTransition):
            finding.add_evidence(Evidence.create("x", "y"))

    def test_add_recommendation(self) -> None:
        finding = make_finding()
        finding.add_recommendation(Recommendation("Patch", "Upgrade", Severity.HIGH))
        assert len(finding.recommendations) == 1


class TestStatusTransitions:
    def test_open_to_confirmed_to_remediated(self) -> None:
        finding = make_finding()
        finding.confirm()
        assert finding.status is FindingStatus.CONFIRMED
        finding.mark_remediated()
        assert finding.status is FindingStatus.REMEDIATED

    def test_cannot_remediate_an_open_finding(self) -> None:
        # Must be confirmed first.
        with pytest.raises(IllegalStateTransition):
            make_finding().mark_remediated()

    def test_cannot_transition_out_of_terminal_state(self) -> None:
        finding = make_finding()
        finding.mark_false_positive()
        with pytest.raises(IllegalStateTransition) as excinfo:
            finding.confirm()
        assert excinfo.value.current is FindingStatus.FALSE_POSITIVE
