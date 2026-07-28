from __future__ import annotations

from collections.abc import Sequence

from kingsec.domain.compliance import (
    ComplianceFramework,
    ComplianceStatus,
    FindingControlMapping,
    GapAnalysis,
)

from .coverage import ComplianceCoverageCalculator


class ComplianceGapAnalyzer:
    """Identifies gaps between framework controls and assessed findings."""

    def __init__(self) -> None:
        self._coverage_calc = ComplianceCoverageCalculator()

    def analyze(
        self,
        framework: ComplianceFramework,
        mappings: Sequence[FindingControlMapping],
    ) -> list[GapAnalysis]:
        unmapped = self._coverage_calc.get_unmapped_controls(framework, mappings)
        gaps: list[GapAnalysis] = []

        for ctrl in unmapped:
            gaps.append(
                GapAnalysis(
                    control=ctrl,
                    status=ComplianceStatus.NOT_ASSESSED,
                    mapped_findings=(),
                    recommendation=f"Assess control {ctrl.control_id}: {ctrl.title}",
                )
            )

        return gaps

    def analyze_all(
        self,
        mappings: Sequence[FindingControlMapping],
        enabled_frameworks: list[ComplianceFramework] | None = None,
    ) -> dict[str, list[GapAnalysis]]:
        frameworks = enabled_frameworks or list(ComplianceFramework)
        result: dict[str, list[GapAnalysis]] = {}

        for framework in frameworks:
            gaps = self.analyze(framework, mappings)
            result[framework.value] = gaps

        return result
