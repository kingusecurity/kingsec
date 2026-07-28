from __future__ import annotations

import uuid
from collections.abc import Sequence
from typing import Any

from kingsec.domain.compliance import (
    ComplianceFramework,
    ComplianceReport,
    FindingControlMapping,
)

from .coverage import ComplianceCoverageCalculator
from .gap_analyzer import ComplianceGapAnalyzer
from .mapper import ComplianceMapper


class ComplianceReportGenerator:
    """Generates compliance reports at various detail levels."""

    def __init__(
        self,
        mapper: ComplianceMapper,
        coverage_calc: ComplianceCoverageCalculator,
        gap_analyzer: ComplianceGapAnalyzer,
    ) -> None:
        self._mapper = mapper
        self._coverage_calc = coverage_calc
        self._gap_analyzer = gap_analyzer

    def generate(
        self,
        assessment_id: str,
        target: str,
        mappings: Sequence[FindingControlMapping] | None = None,
        findings: Sequence[Any] | None = None,
        enabled_frameworks: list[ComplianceFramework] | None = None,
    ) -> ComplianceReport:
        if mappings is None and findings is not None:
            resolved_mappings = self._mapper.map_all(findings)
        elif mappings is not None:
            resolved_mappings = list(mappings)
        else:
            resolved_mappings = []

        frameworks = enabled_frameworks or list(ComplianceFramework)

        coverages = self._coverage_calc.calculate(resolved_mappings, frameworks)
        gaps_raw = self._gap_analyzer.analyze_all(resolved_mappings, frameworks)
        gaps = [g for gap_list in gaps_raw.values() for g in gap_list]

        recommendations = self._build_recommendations(coverages, gaps)

        return ComplianceReport.create(
            report_id=f"comp-{uuid.uuid4().hex[:12]}",
            assessment_id=assessment_id,
            target=target,
            framework_coverages=coverages,
            mappings=resolved_mappings,
            gaps=gaps,
            recommendations=recommendations,
        )

    def generate_executive(self, report: ComplianceReport) -> dict[str, Any]:
        return {
            "report_id": report.id,
            "assessment_id": report.assessment_id,
            "target": report.target,
            "generated_at": report.generated_at.isoformat(),
            "overall_coverage_percent": report.overall_coverage_percent,
            "overall_passed": report.overall_passed,
            "overall_failed": report.overall_failed,
            "overall_not_assessed": report.overall_not_assessed,
            "total_controls": report.total_controls,
            "frameworks": [
                {
                    "framework": fc.framework.value,
                    "coverage_percent": fc.coverage_percent,
                    "passed": fc.passed,
                    "failed": fc.failed,
                    "not_assessed": fc.not_assessed,
                    "total_controls": fc.total_controls,
                }
                for fc in report.framework_coverages
            ],
            "recommendations": list(report.recommendations),
        }

    def generate_technical(self, report: ComplianceReport) -> dict[str, Any]:
        return {
            "report_id": report.id,
            "assessment_id": report.assessment_id,
            "target": report.target,
            "generated_at": report.generated_at.isoformat(),
            "overall_coverage_percent": report.overall_coverage_percent,
            "frameworks": [
                {
                    "framework": fc.framework.value,
                    "coverage_percent": fc.coverage_percent,
                    "total_controls": fc.total_controls,
                    "passed": fc.passed,
                    "failed": fc.failed,
                    "not_assessed": fc.not_assessed,
                }
                for fc in report.framework_coverages
            ],
            "finding_mappings": [
                {
                    "finding_id": m.finding_id,
                    "finding_title": m.finding_title,
                    "severity": m.severity,
                    "controls": [
                        {
                            "framework": c.framework.value,
                            "control_id": str(c.control_id),
                            "title": c.title,
                            "category": c.category,
                        }
                        for c in m.controls
                    ],
                }
                for m in report.mappings
            ],
            "recommendations": list(report.recommendations),
        }

    def generate_gap_remediation(self, report: ComplianceReport) -> dict[str, Any]:
        return {
            "report_id": report.id,
            "assessment_id": report.assessment_id,
            "target": report.target,
            "generated_at": report.generated_at.isoformat(),
            "total_gaps": len(report.gaps),
            "gaps": [
                {
                    "framework": g.control.framework.value,
                    "control_id": str(g.control.control_id),
                    "title": g.control.title,
                    "category": g.control.category,
                    "status": g.status.value,
                    "recommendation": g.recommendation,
                }
                for g in report.gaps
            ],
        }

    def _build_recommendations(
        self,
        coverages: list[Any],
        gaps: list[Any],
    ) -> list[str]:
        recs: list[str] = []
        for fc in coverages:
            if fc.coverage_percent < 50:
                recs.append(f"Critical: {fc.framework.value} coverage is only {fc.coverage_percent}%. Prioritize assessment of unaddressed controls.")
            elif fc.coverage_percent < 80:
                recs.append(f"Improvement needed: {fc.framework.value} coverage is at {fc.coverage_percent}%. Review {fc.not_assessed} unassessed controls.")

        severity = 0
        for fc in coverages:
            if fc.failed > severity:
                severity = fc.failed

        if gaps:
            frameworks_with_gaps = {g.control.framework.value for g in gaps}
            recs.append(f"Gaps identified in {len(frameworks_with_gaps)} framework(s). Address {len(gaps)} unassessed controls.")

        if not recs:
            recs.append("All frameworks have acceptable coverage levels.")

        return recs
