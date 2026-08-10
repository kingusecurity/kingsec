"""Finding entity: invariants, identity, evidence accrual, status transitions."""

from __future__ import annotations

from datetime import UTC, datetime

import pytest
from tests.unit.domain.conftest import make_finding

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


class TestConstruction:
    def test_starts_open(self) -> None:
        assert make_finding().status is FindingStatus.OPEN

    def test_requires_non_empty_title(self) -> None:
        with pytest.raises(InvariantViolation):
            Finding.create("", "desc", Severity.LOW)

    def test_requires_severity_type(self) -> None:
        with pytest.raises(InvariantViolation):
            Finding(FindingId.generate(), "t", "d", "high")  # type: ignore[arg-type]


class TestCveCvssData:
    def test_defaults_to_no_cve_data(self) -> None:
        finding = Finding.create("Open port", "desc", Severity.LOW)
        assert finding.cve_ids == ()
        assert finding.cwe_ids == ()
        assert finding.cvss_score is None
        assert finding.cvss_vector is None

    def test_carries_real_cve_cvss_data_when_given(self) -> None:
        finding = Finding.create(
            "CVE-2026-53666 — react-router",
            "desc",
            Severity.MEDIUM,
            cve_ids=("CVE-2026-53666",),
            cwe_ids=("CWE-470",),
            cvss_score=6.1,
            cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N",
        )
        assert finding.cve_ids == ("CVE-2026-53666",)
        assert finding.cwe_ids == ("CWE-470",)
        assert finding.cvss_score == 6.1
        assert finding.cvss_vector == "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N"

    def test_rejects_cvss_score_above_ten(self) -> None:
        with pytest.raises(InvariantViolation):
            Finding.create("t", "d", Severity.LOW, cvss_score=10.1)

    def test_rejects_negative_cvss_score(self) -> None:
        with pytest.raises(InvariantViolation):
            Finding.create("t", "d", Severity.LOW, cvss_score=-0.1)

    def test_accepts_cvss_score_boundaries(self) -> None:
        assert Finding.create("t", "d", Severity.LOW, cvss_score=0.0).cvss_score == 0.0
        assert Finding.create("t", "d", Severity.LOW, cvss_score=10.0).cvss_score == 10.0

    def test_reconstitute_round_trips_cve_data(self) -> None:
        finding = Finding.reconstitute(
            finding_id=FindingId.generate(),
            title="t",
            description="d",
            severity=Severity.HIGH,
            status=FindingStatus.OPEN,
            discovered_at=datetime.now(UTC),
            cve_ids=("CVE-2024-1",),
            cwe_ids=("CWE-1",),
            cvss_score=9.8,
            cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
        )
        assert finding.cve_ids == ("CVE-2024-1",)
        assert finding.cvss_score == 9.8


class TestIdentity:
    def test_equality_is_by_id_not_content(self) -> None:
        fid = FindingId.generate()
        a = Finding(fid, "Title A", "desc", Severity.LOW)
        b = Finding(fid, "Title B", "different", Severity.CRITICAL)
        assert a == b  # same id -> same entity
        assert hash(a) == hash(b)

    def test_different_ids_are_not_equal(self) -> None:
        assert make_finding() != make_finding()


class TestEvidenceAccrual:
    def test_add_evidence_returns_immutable_view(self) -> None:
        finding = make_finding()
        finding.add_evidence(Evidence.create("resp", "500 error"))
        evidence = finding.evidence
        assert len(evidence) == 1
        assert isinstance(evidence, tuple)  # callers cannot mutate internals

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
