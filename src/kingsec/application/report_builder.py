"""Report Builder — assembles a complete Report from pipeline outputs.

Pure application layer, stateless, deterministic. Never mutates inputs.
"""

from __future__ import annotations

from collections import Counter, defaultdict
from datetime import datetime, timezone
from typing import TYPE_CHECKING

from kingsec.application.report import (
    Appendix, AssetEntry, AssetSummary, AttackPathSection,
    ExecutiveSummary, FindingEntry, FindingSection,
    RecommendationEntry, RecommendationSection, Report, RiskSummary,
    TechnicalSummary,
)

if TYPE_CHECKING:
    from kingsec.application.attack_path import AttackGraph
    from kingsec.application.correlation import CorrelatedFinding
    from kingsec.application.enrichment import EnrichedFinding
    from kingsec.application.normalization import NormalizedFinding
    from kingsec.application.risk import RiskAssessment


_SEVERITY_ORDER: dict[str, int] = {
    "CRITICAL": 0,
    "HIGH": 1,
    "MEDIUM": 2,
    "LOW": 3,
    "INFORMATIONAL": 4,
}


class ReportBuilder:
    """Stateless builder that assembles a complete Report from pipeline outputs."""

    def build(
        self,
        normalized_findings: list[NormalizedFinding],
        correlated_findings: list[CorrelatedFinding],
        enriched_findings: list[EnrichedFinding],
        risk_assessments: list[RiskAssessment],
        attack_graph: AttackGraph,
    ) -> Report:
        """Assemble a complete Report from all pipeline outputs."""
        enriched_map = {f.correlation_id: f for f in enriched_findings}
        risk_map = {a.correlation_id: a for a in risk_assessments}

        executive_summary = self._build_executive_summary(
            normalized_findings, correlated_findings, enriched_findings,
            risk_assessments, enriched_map,
        )
        technical_summary = self._build_technical_summary(
            normalized_findings, correlated_findings, enriched_findings,
            risk_assessments, enriched_map,
        )
        risk_summary = self._build_risk_summary(
            risk_assessments, enriched_findings,
        )
        asset_summary = self._build_asset_summary(
            enriched_findings, risk_map,
        )
        finding_section = self._build_finding_section(
            enriched_findings, risk_map,
        )
        attack_path_section = AttackPathSection(
            total_paths=attack_graph.total_paths,
            highest_score=attack_graph.highest_score,
            average_score=attack_graph.average_score,
            graph=attack_graph,
        )
        recommendation_section = self._build_recommendation_section(
            enriched_findings, risk_map,
        )
        appendix = self._build_appendix(normalized_findings)

        return Report(
            report_id=f"rpt-{datetime.now(timezone.utc).strftime('%Y%m%d%H%M%S')}",
            title="KingSec Security Report",
            created_at=datetime.now(timezone.utc),
            executive_summary=executive_summary,
            technical_summary=technical_summary,
            risk_summary=risk_summary,
            asset_summary=asset_summary,
            finding_section=finding_section,
            attack_path_section=attack_path_section,
            recommendation_section=recommendation_section,
            appendix=appendix,
        )

    # ------------------------------------------------------------------
    # Section builders
    # ------------------------------------------------------------------

    @staticmethod
    def _build_executive_summary(
        normalized_findings: list[NormalizedFinding],
        correlated_findings: list[CorrelatedFinding],
        enriched_findings: list[EnrichedFinding],
        risk_assessments: list[RiskAssessment],
        enriched_map: dict[str, EnrichedFinding],
    ) -> ExecutiveSummary:
        total_findings = len(normalized_findings)
        total_correlated = len(correlated_findings)
        total_enriched = len(enriched_findings)
        total_risk = len(risk_assessments)

        scores = [a.score for a in risk_assessments]
        top_score = max(scores) if scores else 0
        avg_score = sum(scores) / len(scores) if scores else 0.0

        severity_counts: Counter[str] = Counter()
        for a in risk_assessments:
            severity_counts[a.risk_level] += 1

        all_assets: set[str] = set()
        for f in enriched_findings:
            all_assets.update(f.affected_assets)
        total_assets = len(all_assets)

        summary_text = (
            f"Security scan found {total_findings} findings "
            f"({severity_counts.get('Critical', 0)} critical, "
            f"{severity_counts.get('High', 0)} high, "
            f"{severity_counts.get('Medium', 0)} medium) "
            f"across {total_assets} assets. "
            f"Top risk score: {top_score}/100."
        )

        return ExecutiveSummary(
            total_findings=total_findings,
            total_correlated=total_correlated,
            total_enriched=total_enriched,
            total_risk_assessments=total_risk,
            critical_count=severity_counts.get("Critical", 0),
            high_count=severity_counts.get("High", 0),
            medium_count=severity_counts.get("Medium", 0),
            low_count=severity_counts.get("Low", 0),
            informational_count=severity_counts.get("Informational", 0),
            top_risk_score=top_score,
            average_risk_score=round(avg_score, 2),
            total_assets=total_assets,
            summary_text=summary_text,
        )

    @staticmethod
    def _build_technical_summary(
        normalized_findings: list[NormalizedFinding],
        correlated_findings: list[CorrelatedFinding],
        enriched_findings: list[EnrichedFinding],
        risk_assessments: list[RiskAssessment],
        enriched_map: dict[str, EnrichedFinding],
    ) -> TechnicalSummary:
        severity_breakdown: Counter[str] = Counter()
        category_breakdown: Counter[str] = Counter()
        scanner_coverage: Counter[str] = Counter()

        for f in enriched_findings:
            severity_breakdown[f.severity.name] += 1
            category_breakdown[f.category] += 1
            for src in f.scanner_sources:
                scanner_coverage[src] += 1

        return TechnicalSummary(
            total_findings=len(normalized_findings),
            total_correlations=len(correlated_findings),
            total_enriched=len(enriched_findings),
            total_risk_assessments=len(risk_assessments),
            severity_breakdown=dict(severity_breakdown),
            category_breakdown=dict(category_breakdown),
            scanner_coverage=dict(scanner_coverage),
        )

    @staticmethod
    def _build_risk_summary(
        risk_assessments: list[RiskAssessment],
        enriched_findings: list[EnrichedFinding],
    ) -> RiskSummary:
        score_distribution: Counter[str] = Counter()
        for a in risk_assessments:
            score_distribution[a.risk_level] += 1

        scores = [a.score for a in risk_assessments]
        avg_score = sum(scores) / len(scores) if scores else 0.0
        highest = max(scores) if scores else 0
        lowest = min(scores) if scores else 0

        top_factors: list[str] = []
        seen: set[str] = set()
        for f in enriched_findings:
            for rf in f.risk_factors:
                if rf not in seen:
                    seen.add(rf)
                    top_factors.append(rf)
        top_factors.sort()

        return RiskSummary(
            score_distribution=dict(score_distribution),
            average_score=round(avg_score, 2),
            highest_score=highest,
            lowest_score=lowest,
            top_risk_factors=tuple(top_factors),
        )

    @staticmethod
    def _build_asset_summary(
        enriched_findings: list[EnrichedFinding],
        risk_map: dict[str, RiskAssessment],
    ) -> AssetSummary:
        asset_findings: dict[str, list[EnrichedFinding]] = defaultdict(list)
        for f in enriched_findings:
            for asset in f.affected_assets:
                asset_findings[asset].append(f)

        entries: list[AssetEntry] = []
        for asset in sorted(asset_findings):
            findings = asset_findings[asset]
            scores = [
                risk_map[f.correlation_id].score
                for f in findings
                if f.correlation_id in risk_map
            ]
            high = max(scores) if scores else 0
            avg = sum(scores) / len(scores) if scores else 0.0
            entries.append(AssetEntry(
                asset=asset,
                finding_count=len(findings),
                highest_risk_score=high,
                average_risk_score=round(avg, 2),
            ))

        entries_tuple = tuple(entries)
        return AssetSummary(
            entries=entries_tuple,
            total_assets=len(entries_tuple),
        )

    @staticmethod
    def _build_finding_section(
        enriched_findings: list[EnrichedFinding],
        risk_map: dict[str, RiskAssessment],
    ) -> FindingSection:
        entries: list[FindingEntry] = []
        for f in sorted(enriched_findings, key=lambda x: x.correlation_id):
            ra = risk_map.get(f.correlation_id)
            risk_score = ra.score if ra else 0
            risk_level = ra.risk_level if ra else "Unknown"
            priority = ra.priority if ra else "None"

            entries.append(FindingEntry(
                correlation_id=f.correlation_id,
                title=f.title,
                severity=f.severity.name,
                category=f.category,
                confidence=f.confidence,
                scanner_sources=f.scanner_sources,
                affected_assets=f.affected_assets,
                service=f.service,
                port=f.port,
                protocol=f.protocol,
                attack_surface=f.attack_surface,
                risk_score=risk_score,
                risk_level=risk_level,
                priority=priority,
            ))

        entries.sort(key=lambda e: (_SEVERITY_ORDER.get(e.severity, 99), -e.risk_score, e.correlation_id))

        entries_tuple = tuple(entries)

        severity_breakdown: Counter[str] = Counter()
        for e in entries_tuple:
            severity_breakdown[e.severity] += 1

        return FindingSection(
            entries=entries_tuple,
            total_count=len(entries_tuple),
            severity_breakdown=dict(severity_breakdown),
        )

    @staticmethod
    def _build_recommendation_section(
        enriched_findings: list[EnrichedFinding],
        risk_map: dict[str, RiskAssessment],
    ) -> RecommendationSection:
        entries: list[RecommendationEntry] = []
        for f in sorted(enriched_findings, key=lambda x: x.correlation_id):
            if not f.recommendations:
                continue
            ra = risk_map.get(f.correlation_id)
            risk_score = ra.score if ra else 0
            entries.append(RecommendationEntry(
                finding_title=f.title,
                severity=f.severity.name,
                risk_score=risk_score,
                correlation_id=f.correlation_id,
                recommendations=f.recommendations,
            ))

        entries.sort(key=lambda e: (-e.risk_score, e.correlation_id))

        total_recs = sum(len(e.recommendations) for e in entries)
        return RecommendationSection(
            entries=tuple(entries),
            total_recommendations=total_recs,
        )

    @staticmethod
    def _build_appendix(
        normalized_findings: list[NormalizedFinding],
    ) -> Appendix:
        versions: dict[str, str | None] = {}
        for nf in normalized_findings:
            if nf.scanner_id not in versions:
                versions[nf.scanner_id] = nf.scanner_version
        return Appendix(
            scanner_versions=versions,
            total_plugins=len(versions),
            generated_at=datetime.now(timezone.utc),
            generated_by="KingSec Report Builder",
        )
