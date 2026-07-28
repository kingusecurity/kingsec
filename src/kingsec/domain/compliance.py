from __future__ import annotations

from dataclasses import dataclass
from datetime import UTC, datetime
from enum import StrEnum

from .errors import InvariantViolation


class ComplianceFramework(StrEnum):
    CIS_V8 = "cis_v8"
    NIST_CSF_2 = "nist_csf_2"
    OWASP_TOP_10 = "owasp_top_10"
    CWE = "cwe"
    CVE = "cve"
    MITRE_ATT_CK = "mitre_att_ck"
    ISO_27001 = "iso_27001"
    PCI_DSS_4 = "pci_dss_4"


class ComplianceStatus(StrEnum):
    PASSED = "passed"
    FAILED = "failed"
    NOT_ASSESSED = "not_assessed"


@dataclass(frozen=True, slots=True)
class ControlId:
    value: str

    def __post_init__(self) -> None:
        if not self.value or not self.value.strip():
            raise InvariantViolation("ControlId must not be empty")

    def __str__(self) -> str:
        return self.value


@dataclass(frozen=True, slots=True)
class FrameworkControl:
    framework: ComplianceFramework
    control_id: ControlId
    title: str
    description: str
    category: str = ""

    def __str__(self) -> str:
        return f"{self.framework.value}/{self.control_id}"


@dataclass(frozen=True, slots=True)
class FindingControlMapping:
    finding_id: str
    finding_title: str
    severity: str
    controls: tuple[FrameworkControl, ...] = ()


@dataclass(frozen=True, slots=True)
class FrameworkCoverage:
    framework: ComplianceFramework
    total_controls: int
    passed: int
    failed: int
    not_assessed: int

    @property
    def coverage_percent(self) -> float:
        if self.total_controls == 0:
            return 100.0
        return round((self.passed / self.total_controls) * 100, 1)

    @property
    def passed_percent(self) -> float:
        if self.total_controls == 0:
            return 0.0
        return round((self.passed / self.total_controls) * 100, 1)


@dataclass(frozen=True, slots=True)
class GapAnalysis:
    control: FrameworkControl
    status: ComplianceStatus
    mapped_findings: tuple[str, ...] = ()
    recommendation: str = ""


@dataclass(frozen=True, slots=True)
class ComplianceReport:
    id: str
    assessment_id: str
    target: str
    generated_at: datetime
    framework_coverages: tuple[FrameworkCoverage, ...]
    mappings: tuple[FindingControlMapping, ...]
    gaps: tuple[GapAnalysis, ...]
    overall_coverage_percent: float
    overall_passed: int
    overall_failed: int
    overall_not_assessed: int
    total_controls: int
    recommendations: tuple[str, ...] = ()

    @classmethod
    def create(
        cls,
        report_id: str,
        assessment_id: str,
        target: str,
        framework_coverages: list[FrameworkCoverage],
        mappings: list[FindingControlMapping],
        gaps: list[GapAnalysis],
        recommendations: list[str] | None = None,
        generated_at: datetime | None = None,
    ) -> ComplianceReport:
        total = sum(fc.total_controls for fc in framework_coverages) or 1
        overall_passed = sum(fc.passed for fc in framework_coverages)
        overall_failed = sum(fc.failed for fc in framework_coverages)
        overall_not_assessed = sum(fc.not_assessed for fc in framework_coverages)
        overall_coverage = round((overall_passed / total) * 100, 1)

        return cls(
            id=report_id,
            assessment_id=assessment_id,
            target=target,
            generated_at=generated_at or datetime.now(UTC),
            framework_coverages=tuple(framework_coverages),
            mappings=tuple(mappings),
            gaps=tuple(gaps),
            overall_coverage_percent=overall_coverage,
            overall_passed=overall_passed,
            overall_failed=overall_failed,
            overall_not_assessed=overall_not_assessed,
            total_controls=total,
            recommendations=tuple(recommendations or []),
        )
