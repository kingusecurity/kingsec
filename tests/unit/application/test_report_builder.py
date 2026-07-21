"""Report Builder: comprehensive tests."""

from __future__ import annotations

from datetime import UTC, datetime

import pytest

from kingsec.application.attack_path import (
    AttackEdge,
    AttackGraph,
    AttackNode,
    AttackPath,
)
from kingsec.application.correlation import CorrelatedFinding
from kingsec.application.enrichment import EnrichedFinding
from kingsec.application.normalization import NormalizedFinding
from kingsec.application.report import (
    Report,
)
from kingsec.application.report_builder import ReportBuilder
from kingsec.application.risk import RiskAssessment, RiskFactor
from kingsec.domain import Evidence, Recommendation, Severity

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

_BUILDER = ReportBuilder()
_NOW = datetime(2026, 7, 17, tzinfo=UTC)


def _make_evidence(text: str = "evidence text") -> Evidence:
    return Evidence(summary=text, detail=text, collected_at=_NOW)


def _make_rec(title: str = "Patch", priority: Severity = Severity.HIGH) -> Recommendation:
    return Recommendation(title=title, description=title, priority=priority)


def _make_normalized(
    finding_id: str = "nf-001",
    title: str = "SSH Vulnerability",
    scanner_id: str = "nuclei",
    scanner_version: str | None = "3.2.1",
    severity: Severity = Severity.HIGH,
    category: str = "vulnerability",
    affected_assets: tuple[str, ...] = ("10.0.0.1",),
) -> NormalizedFinding:
    return NormalizedFinding(
        finding_id=finding_id,
        title=title,
        description=f"{title} detected",
        severity=severity,
        scanner_id=scanner_id,
        scanner_version=scanner_version,
        evidence=(_make_evidence(),),
        recommendations=(_make_rec(),),
        references=(),
        affected_assets=affected_assets,
        raw_data="{}",
        discovered_at=_NOW,
        tags=(),
        category=category,
    )


def _make_correlated(
    correlation_id: str = "corr-001",
    title: str = "SSH Vulnerability",
    severity: Severity = Severity.HIGH,
    category: str = "vulnerability",
    affected_assets: tuple[str, ...] = ("10.0.0.1",),
    scanner_sources: tuple[str, ...] = ("nuclei",),
    merged_findings: tuple[NormalizedFinding, ...] | None = None,
    confidence: float = 0.8,
) -> CorrelatedFinding:
    if merged_findings is None:
        merged_findings = (_make_normalized(finding_id=f"nf-{correlation_id}"),)
    return CorrelatedFinding(
        correlation_id=correlation_id,
        title=title,
        severity=severity,
        category=category,
        affected_assets=affected_assets,
        references=(),
        scanner_sources=scanner_sources,
        merged_findings=merged_findings,
        confidence=confidence,
        description=f"{title} detected",
        recommendations=(),
        tags=(),
    )


def _make_enriched(
    correlation_id: str = "corr-001",
    title: str = "SSH Vulnerability",
    severity: Severity = Severity.HIGH,
    category: str = "vulnerability",
    affected_assets: tuple[str, ...] = ("10.0.0.1",),
    scanner_sources: tuple[str, ...] = ("nuclei",),
    confidence: float = 0.8,
    service: str | None = "SSH",
    port: int | None = 22,
    protocol: str | None = "TCP",
    attack_surface: str | None = "Network Service",
    risk_factors: tuple[str, ...] = ("Remote Code Execution",),
    recommendations: tuple[str, ...] = ("Patch OpenSSH",),
    business_impact: str | None = "High",
    exploit_likelihood: str | None = "Medium",
    remediation_complexity: str | None = "Medium",
    priority: str = "High",
) -> EnrichedFinding:
    return EnrichedFinding(
        correlation_id=correlation_id,
        title=title,
        description=f"{title} detected",
        severity=severity,
        category=category,
        confidence=confidence,
        scanner_sources=scanner_sources,
        affected_assets=affected_assets,
        references=(),
        recommendations=recommendations,
        tags=(),
        software=(),
        service=service,
        protocol=protocol,
        port=port,
        technology=(),
        operating_system=None,
        attack_surface=attack_surface,
        risk_factors=risk_factors,
        business_impact=business_impact,
        exploit_likelihood=exploit_likelihood,
        remediation_complexity=remediation_complexity,
        priority=priority,
        metadata={},
    )


def _make_factor(
    name: str = "severity",
    weight: int = 30,
    contribution: int = 22,
) -> RiskFactor:
    return RiskFactor(
        name=name,
        weight=weight,
        contribution=contribution,
        description=f"{name} contributed {contribution}",
    )


def _make_assessment(
    correlation_id: str = "corr-001",
    score: int = 75,
    risk_level: str = "High",
    priority: str = "High",
) -> RiskAssessment:
    return RiskAssessment(
        correlation_id=correlation_id,
        score=score,
        risk_level=risk_level,
        priority=priority,
        reasoning=f"Score {score}/100",
        factors=(_make_factor("severity"), _make_factor("confidence", 15, 10)),
    )


def _make_attack_node(correlation_id: str = "corr-001") -> AttackNode:
    return AttackNode(
        node_id=f"node-{correlation_id}",
        correlation_id=correlation_id,
        title="SSH Vuln",
        severity="HIGH",
        category="vulnerability",
        attack_surface="Network Service",
        service="SSH",
        port=22,
        protocol="TCP",
        asset="10.0.0.1",
        risk_score=75,
        risk_level="High",
    )


def _make_attack_graph(
    total_paths: int = 1,
    highest_score: int = 75,
) -> AttackGraph:
    n1 = _make_attack_node("corr-001")
    p = AttackPath(
        path_id="path-1",
        nodes=(n1,),
        edges=(),
        attack_score=75,
        confidence=0.35,
        estimated_impact="High",
        attack_complexity="Simple",
        likelihood="Medium",
        reasoning="Single step.",
        recommendations=("Patch OpenSSH",),
    )
    return AttackGraph(
        paths=(p,),
        total_paths=total_paths,
        highest_score=highest_score,
        average_score=float(highest_score),
        metadata={"total_assessments": "1"},
    )


def _make_pipeline_single() -> tuple[
    list[NormalizedFinding],
    list[CorrelatedFinding],
    list[EnrichedFinding],
    list[RiskAssessment],
    AttackGraph,
]:
    nf = _make_normalized()
    cf = _make_correlated(merged_findings=(nf,))
    ef = _make_enriched()
    ra = _make_assessment()
    ag = _make_attack_graph()
    return [nf], [cf], [ef], [ra], ag


# ===========================================================================
# ReportBuilder — construction
# ===========================================================================


class TestBuilderConstruction:
    def test_creates_report(self) -> None:
        nfs, cfs, efs, ras, ag = _make_pipeline_single()
        report = _BUILDER.build(nfs, cfs, efs, ras, ag)
        assert isinstance(report, Report)

    def test_has_all_sections(self) -> None:
        nfs, cfs, efs, ras, ag = _make_pipeline_single()
        report = _BUILDER.build(nfs, cfs, efs, ras, ag)
        assert report.executive_summary is not None
        assert report.technical_summary is not None
        assert report.risk_summary is not None
        assert report.asset_summary is not None
        assert report.finding_section is not None
        assert report.attack_path_section is not None
        assert report.recommendation_section is not None
        assert report.appendix is not None

    def test_immutable_output(self) -> None:
        nfs, cfs, efs, ras, ag = _make_pipeline_single()
        report = _BUILDER.build(nfs, cfs, efs, ras, ag)
        with pytest.raises(AttributeError):
            report.title = "Changed"  # type: ignore[misc]


# ===========================================================================
# Empty report
# ===========================================================================


class TestEmptyReport:
    def test_empty_inputs(self) -> None:
        n1 = _make_attack_node("corr-001")
        p = AttackPath(
            path_id="path-1", nodes=(n1,), edges=(),
            attack_score=0, confidence=0.0,
            estimated_impact="None", attack_complexity="Simple",
            likelihood="Low", reasoning="Empty.", recommendations=(),
        )
        ag = AttackGraph(
            paths=(p,), total_paths=1, highest_score=0,
            average_score=0.0, metadata={"total_assessments": "0"},
        )
        report = _BUILDER.build([], [], [], [], ag)
        assert report.executive_summary.total_findings == 0
        assert report.executive_summary.total_correlated == 0
        assert report.executive_summary.total_enriched == 0
        assert report.executive_summary.total_risk_assessments == 0

    def test_empty_finding_section(self) -> None:
        n1 = _make_attack_node("corr-001")
        p = AttackPath(
            path_id="path-1", nodes=(n1,), edges=(),
            attack_score=0, confidence=0.0,
            estimated_impact="None", attack_complexity="Simple",
            likelihood="Low", reasoning="Empty.", recommendations=(),
        )
        ag = AttackGraph(
            paths=(p,), total_paths=1, highest_score=0,
            average_score=0.0, metadata={"total_assessments": "0"},
        )
        report = _BUILDER.build([], [], [], [], ag)
        assert report.finding_section.total_count == 0
        assert report.finding_section.entries == ()

    def test_empty_recommendation_section(self) -> None:
        n1 = _make_attack_node("corr-001")
        p = AttackPath(
            path_id="path-1", nodes=(n1,), edges=(),
            attack_score=0, confidence=0.0,
            estimated_impact="None", attack_complexity="Simple",
            likelihood="Low", reasoning="Empty.", recommendations=(),
        )
        ag = AttackGraph(
            paths=(p,), total_paths=1, highest_score=0,
            average_score=0.0, metadata={"total_assessments": "0"},
        )
        report = _BUILDER.build([], [], [], [], ag)
        assert report.recommendation_section.total_recommendations == 0
        assert report.recommendation_section.entries == ()

    def test_empty_asset_summary(self) -> None:
        n1 = _make_attack_node("corr-001")
        p = AttackPath(
            path_id="path-1", nodes=(n1,), edges=(),
            attack_score=0, confidence=0.0,
            estimated_impact="None", attack_complexity="Simple",
            likelihood="Low", reasoning="Empty.", recommendations=(),
        )
        ag = AttackGraph(
            paths=(p,), total_paths=1, highest_score=0,
            average_score=0.0, metadata={"total_assessments": "0"},
        )
        report = _BUILDER.build([], [], [], [], ag)
        assert report.asset_summary.total_assets == 0
        assert report.asset_summary.entries == ()

    def test_empty_risk_summary(self) -> None:
        n1 = _make_attack_node("corr-001")
        p = AttackPath(
            path_id="path-1", nodes=(n1,), edges=(),
            attack_score=0, confidence=0.0,
            estimated_impact="None", attack_complexity="Simple",
            likelihood="Low", reasoning="Empty.", recommendations=(),
        )
        ag = AttackGraph(
            paths=(p,), total_paths=1, highest_score=0,
            average_score=0.0, metadata={"total_assessments": "0"},
        )
        report = _BUILDER.build([], [], [], [], ag)
        assert report.risk_summary.score_distribution == {}
        assert report.risk_summary.average_score == 0.0
        assert report.risk_summary.highest_score == 0

    def test_empty_appendix(self) -> None:
        n1 = _make_attack_node("corr-001")
        p = AttackPath(
            path_id="path-1", nodes=(n1,), edges=(),
            attack_score=0, confidence=0.0,
            estimated_impact="None", attack_complexity="Simple",
            likelihood="Low", reasoning="Empty.", recommendations=(),
        )
        ag = AttackGraph(
            paths=(p,), total_paths=1, highest_score=0,
            average_score=0.0, metadata={"total_assessments": "0"},
        )
        report = _BUILDER.build([], [], [], [], ag)
        assert report.appendix.scanner_versions == {}
        assert report.appendix.total_plugins == 0


# ===========================================================================
# ExecutiveSummary
# ===========================================================================


class TestExecutiveSummary:
    def test_counts(self) -> None:
        nfs = [_make_normalized(finding_id="nf-1"), _make_normalized(finding_id="nf-2")]
        cfs = [_make_correlated(correlation_id="corr-001"), _make_correlated(correlation_id="corr-002")]
        efs = [_make_enriched(correlation_id="corr-001"), _make_enriched(correlation_id="corr-002")]
        ras = [_make_assessment(correlation_id="corr-001", score=80, risk_level="Critical"),
               _make_assessment(correlation_id="corr-002", score=50, risk_level="Medium")]
        n1 = _make_attack_node("corr-001")
        n2 = _make_attack_node("corr-002")
        e = AttackEdge(source_id="node-corr-001", target_id="node-corr-002",
                        relationship="same_asset", confidence=0.8)
        p = AttackPath(path_id="path-1", nodes=(n1, n2), edges=(e,),
                       attack_score=68, confidence=0.8,
                       estimated_impact="High", attack_complexity="Moderate",
                       likelihood="Medium", reasoning="Two-step.",
                       recommendations=())
        ag = AttackGraph(paths=(p,), total_paths=1, highest_score=68,
                         average_score=68.0, metadata={})
        report = _BUILDER.build(nfs, cfs, efs, ras, ag)
        es = report.executive_summary
        assert es.total_findings == 2
        assert es.total_correlated == 2
        assert es.total_enriched == 2
        assert es.total_risk_assessments == 2

    def test_severity_counts(self) -> None:
        nfs = [_make_normalized(finding_id="nf-1")]
        cfs = [_make_correlated(correlation_id="corr-001")]
        efs = [_make_enriched(correlation_id="corr-001")]
        ras = [
            _make_assessment(correlation_id="corr-001", score=85, risk_level="Critical"),
        ]
        ag = _make_attack_graph(highest_score=85)
        report = _BUILDER.build(nfs, cfs, efs, ras, ag)
        es = report.executive_summary
        assert es.critical_count == 1
        assert es.high_count == 0

    def test_top_risk_score(self) -> None:
        nfs = [_make_normalized(finding_id="nf-1")]
        cfs = [_make_correlated(correlation_id="corr-001")]
        efs = [_make_enriched(correlation_id="corr-001")]
        ras = [_make_assessment(correlation_id="corr-001", score=95)]
        ag = _make_attack_graph(highest_score=95)
        report = _BUILDER.build(nfs, cfs, efs, ras, ag)
        assert report.executive_summary.top_risk_score == 95

    def test_average_risk_score(self) -> None:
        nfs = [_make_normalized(finding_id="nf-1"), _make_normalized(finding_id="nf-2")]
        cfs = [_make_correlated(correlation_id="corr-001"), _make_correlated(correlation_id="corr-002")]
        efs = [_make_enriched(correlation_id="corr-001"), _make_enriched(correlation_id="corr-002")]
        ras = [_make_assessment(correlation_id="corr-001", score=80),
               _make_assessment(correlation_id="corr-002", score=40)]
        n1 = _make_attack_node("corr-001")
        n2 = _make_attack_node("corr-002")
        e = AttackEdge(source_id="node-corr-001", target_id="node-corr-002",
                        relationship="same_asset", confidence=0.8)
        p = AttackPath(path_id="path-1", nodes=(n1, n2), edges=(e,),
                       attack_score=64, confidence=0.8,
                       estimated_impact="High", attack_complexity="Moderate",
                       likelihood="Medium", reasoning="Two-step.",
                       recommendations=())
        ag = AttackGraph(paths=(p,), total_paths=1, highest_score=64,
                         average_score=64.0, metadata={})
        report = _BUILDER.build(nfs, cfs, efs, ras, ag)
        assert report.executive_summary.average_risk_score == 60.0

    def test_total_assets(self) -> None:
        nfs = [_make_normalized(finding_id="nf-1")]
        cfs = [_make_correlated(correlation_id="corr-001")]
        efs = [_make_enriched(correlation_id="corr-001",
                               affected_assets=("10.0.0.1", "10.0.0.2"))]
        ras = [_make_assessment(correlation_id="corr-001")]
        ag = _make_attack_graph()
        report = _BUILDER.build(nfs, cfs, efs, ras, ag)
        assert report.executive_summary.total_assets == 2

    def test_summary_text(self) -> None:
        nfs, cfs, efs, ras, ag = _make_pipeline_single()
        report = _BUILDER.build(nfs, cfs, efs, ras, ag)
        text = report.executive_summary.summary_text
        assert "1 findings" in text
        assert "Top risk score" in text


# ===========================================================================
# TechnicalSummary
# ===========================================================================


class TestTechnicalSummary:
    def test_severity_breakdown(self) -> None:
        efs = [
            _make_enriched(correlation_id="corr-001", severity=Severity.CRITICAL),
            _make_enriched(correlation_id="corr-002", severity=Severity.HIGH),
        ]
        ras = [_make_assessment(correlation_id="corr-001"),
               _make_assessment(correlation_id="corr-002")]
        nfs = [_make_normalized(finding_id="nf-1"), _make_normalized(finding_id="nf-2")]
        cfs = [_make_correlated(correlation_id="corr-001"), _make_correlated(correlation_id="corr-002")]
        n1 = _make_attack_node("corr-001")
        n2 = _make_attack_node("corr-002")
        e = AttackEdge(source_id="node-corr-001", target_id="node-corr-002",
                        relationship="same_asset", confidence=0.8)
        p = AttackPath(path_id="path-1", nodes=(n1, n2), edges=(e,),
                       attack_score=68, confidence=0.8,
                       estimated_impact="High", attack_complexity="Moderate",
                       likelihood="Medium", reasoning="Two-step.",
                       recommendations=())
        ag = AttackGraph(paths=(p,), total_paths=1, highest_score=68,
                         average_score=68.0, metadata={})
        report = _BUILDER.build(nfs, cfs, efs, ras, ag)
        sb = report.technical_summary.severity_breakdown
        assert sb.get("CRITICAL") == 1
        assert sb.get("HIGH") == 1

    def test_scanner_coverage(self) -> None:
        efs = [_make_enriched(correlation_id="corr-001",
                               scanner_sources=("nuclei", "nmap"))]
        ras = [_make_assessment(correlation_id="corr-001")]
        nfs = [_make_normalized(finding_id="nf-1")]
        cfs = [_make_correlated(correlation_id="corr-001")]
        ag = _make_attack_graph()
        report = _BUILDER.build(nfs, cfs, efs, ras, ag)
        sc = report.technical_summary.scanner_coverage
        assert sc.get("nuclei") == 1
        assert sc.get("nmap") == 1

    def test_category_breakdown(self) -> None:
        efs = [
            _make_enriched(correlation_id="corr-001", category="vulnerability"),
            _make_enriched(correlation_id="corr-002", category="misconfiguration"),
        ]
        ras = [_make_assessment(correlation_id="corr-001"),
               _make_assessment(correlation_id="corr-002")]
        nfs = [_make_normalized(finding_id="nf-1"), _make_normalized(finding_id="nf-2")]
        cfs = [_make_correlated(correlation_id="corr-001"), _make_correlated(correlation_id="corr-002")]
        n1 = _make_attack_node("corr-001")
        n2 = _make_attack_node("corr-002")
        e = AttackEdge(source_id="node-corr-001", target_id="node-corr-002",
                        relationship="same_asset", confidence=0.8)
        p = AttackPath(path_id="path-1", nodes=(n1, n2), edges=(e,),
                       attack_score=68, confidence=0.8,
                       estimated_impact="High", attack_complexity="Moderate",
                       likelihood="Medium", reasoning="Two-step.",
                       recommendations=())
        ag = AttackGraph(paths=(p,), total_paths=1, highest_score=68,
                         average_score=68.0, metadata={})
        report = _BUILDER.build(nfs, cfs, efs, ras, ag)
        cb = report.technical_summary.category_breakdown
        assert cb.get("vulnerability") == 1
        assert cb.get("misconfiguration") == 1


# ===========================================================================
# RiskSummary
# ===========================================================================


class TestRiskSummary:
    def test_score_distribution(self) -> None:
        ras = [
            _make_assessment(correlation_id="corr-001", score=85, risk_level="Critical"),
            _make_assessment(correlation_id="corr-002", score=70, risk_level="High"),
        ]
        efs = [_make_enriched(correlation_id="corr-001"),
               _make_enriched(correlation_id="corr-002")]
        nfs = [_make_normalized(finding_id="nf-1"), _make_normalized(finding_id="nf-2")]
        cfs = [_make_correlated(correlation_id="corr-001"), _make_correlated(correlation_id="corr-002")]
        n1 = _make_attack_node("corr-001")
        n2 = _make_attack_node("corr-002")
        e = AttackEdge(source_id="node-corr-001", target_id="node-corr-002",
                        relationship="same_asset", confidence=0.8)
        p = AttackPath(path_id="path-1", nodes=(n1, n2), edges=(e,),
                       attack_score=79, confidence=0.8,
                       estimated_impact="High", attack_complexity="Moderate",
                       likelihood="Medium", reasoning="Two-step.",
                       recommendations=())
        ag = AttackGraph(paths=(p,), total_paths=1, highest_score=79,
                         average_score=79.0, metadata={})
        report = _BUILDER.build(nfs, cfs, efs, ras, ag)
        sd = report.risk_summary.score_distribution
        assert sd.get("Critical") == 1
        assert sd.get("High") == 1

    def test_top_risk_factors(self) -> None:
        efs = [_make_enriched(correlation_id="corr-001",
                               risk_factors=("RCE", "SQL Injection"))]
        ras = [_make_assessment(correlation_id="corr-001")]
        nfs = [_make_normalized(finding_id="nf-1")]
        cfs = [_make_correlated(correlation_id="corr-001")]
        ag = _make_attack_graph()
        report = _BUILDER.build(nfs, cfs, efs, ras, ag)
        factors = report.risk_summary.top_risk_factors
        assert "RCE" in factors
        assert "SQL Injection" in factors

    def test_factors_deduplicated(self) -> None:
        efs = [
            _make_enriched(correlation_id="corr-001", risk_factors=("RCE",)),
            _make_enriched(correlation_id="corr-002", risk_factors=("RCE",)),
        ]
        ras = [_make_assessment(correlation_id="corr-001"),
               _make_assessment(correlation_id="corr-002")]
        nfs = [_make_normalized(finding_id="nf-1"), _make_normalized(finding_id="nf-2")]
        cfs = [_make_correlated(correlation_id="corr-001"), _make_correlated(correlation_id="corr-002")]
        n1 = _make_attack_node("corr-001")
        n2 = _make_attack_node("corr-002")
        e = AttackEdge(source_id="node-corr-001", target_id="node-corr-002",
                        relationship="same_asset", confidence=0.8)
        p = AttackPath(path_id="path-1", nodes=(n1, n2), edges=(e,),
                       attack_score=68, confidence=0.8,
                       estimated_impact="High", attack_complexity="Moderate",
                       likelihood="Medium", reasoning="Two-step.",
                       recommendations=())
        ag = AttackGraph(paths=(p,), total_paths=1, highest_score=68,
                         average_score=68.0, metadata={})
        report = _BUILDER.build(nfs, cfs, efs, ras, ag)
        assert len(report.risk_summary.top_risk_factors) == 1

    def test_highest_lowest_score(self) -> None:
        ras = [
            _make_assessment(correlation_id="corr-001", score=90),
            _make_assessment(correlation_id="corr-002", score=30),
        ]
        efs = [_make_enriched(correlation_id="corr-001"),
               _make_enriched(correlation_id="corr-002")]
        nfs = [_make_normalized(finding_id="nf-1"), _make_normalized(finding_id="nf-2")]
        cfs = [_make_correlated(correlation_id="corr-001"), _make_correlated(correlation_id="corr-002")]
        n1 = _make_attack_node("corr-001")
        n2 = _make_attack_node("corr-002")
        e = AttackEdge(source_id="node-corr-001", target_id="node-corr-002",
                        relationship="same_asset", confidence=0.8)
        p = AttackPath(path_id="path-1", nodes=(n1, n2), edges=(e,),
                       attack_score=66, confidence=0.8,
                       estimated_impact="High", attack_complexity="Moderate",
                       likelihood="Medium", reasoning="Two-step.",
                       recommendations=())
        ag = AttackGraph(paths=(p,), total_paths=1, highest_score=66,
                         average_score=66.0, metadata={})
        report = _BUILDER.build(nfs, cfs, efs, ras, ag)
        assert report.risk_summary.highest_score == 90
        assert report.risk_summary.lowest_score == 30


# ===========================================================================
# AssetSummary
# ===========================================================================


class TestAssetSummary:
    def test_per_asset_stats(self) -> None:
        efs = [
            _make_enriched(correlation_id="corr-001",
                           affected_assets=("10.0.0.1",)),
            _make_enriched(correlation_id="corr-002",
                           affected_assets=("10.0.0.2",)),
        ]
        ras = [
            _make_assessment(correlation_id="corr-001", score=90),
            _make_assessment(correlation_id="corr-002", score=50),
        ]
        nfs = [_make_normalized(finding_id="nf-1"), _make_normalized(finding_id="nf-2")]
        cfs = [_make_correlated(correlation_id="corr-001"), _make_correlated(correlation_id="corr-002")]
        n1 = _make_attack_node("corr-001")
        n2 = _make_attack_node("corr-002")
        e = AttackEdge(source_id="node-corr-001", target_id="node-corr-002",
                        relationship="same_asset", confidence=0.8)
        p = AttackPath(path_id="path-1", nodes=(n1, n2), edges=(e,),
                       attack_score=74, confidence=0.8,
                       estimated_impact="High", attack_complexity="Moderate",
                       likelihood="Medium", reasoning="Two-step.",
                       recommendations=())
        ag = AttackGraph(paths=(p,), total_paths=1, highest_score=74,
                         average_score=74.0, metadata={})
        report = _BUILDER.build(nfs, cfs, efs, ras, ag)
        assert report.asset_summary.total_assets == 2

    def test_asset_finding_count(self) -> None:
        efs = [
            _make_enriched(correlation_id="corr-001",
                           affected_assets=("10.0.0.1",)),
            _make_enriched(correlation_id="corr-002",
                           affected_assets=("10.0.0.1",)),
        ]
        ras = [
            _make_assessment(correlation_id="corr-001", score=80),
            _make_assessment(correlation_id="corr-002", score=60),
        ]
        nfs = [_make_normalized(finding_id="nf-1"), _make_normalized(finding_id="nf-2")]
        cfs = [_make_correlated(correlation_id="corr-001"), _make_correlated(correlation_id="corr-002")]
        n1 = _make_attack_node("corr-001")
        n2 = _make_attack_node("corr-002")
        e = AttackEdge(source_id="node-corr-001", target_id="node-corr-002",
                        relationship="same_asset", confidence=0.8)
        p = AttackPath(path_id="path-1", nodes=(n1, n2), edges=(e,),
                       attack_score=72, confidence=0.8,
                       estimated_impact="High", attack_complexity="Moderate",
                       likelihood="Medium", reasoning="Two-step.",
                       recommendations=())
        ag = AttackGraph(paths=(p,), total_paths=1, highest_score=72,
                         average_score=72.0, metadata={})
        report = _BUILDER.build(nfs, cfs, efs, ras, ag)
        entries = report.asset_summary.entries
        assert len(entries) == 1
        assert entries[0].finding_count == 2

    def test_asset_highest_risk(self) -> None:
        efs = [
            _make_enriched(correlation_id="corr-001",
                           affected_assets=("10.0.0.1",)),
            _make_enriched(correlation_id="corr-002",
                           affected_assets=("10.0.0.1",)),
        ]
        ras = [
            _make_assessment(correlation_id="corr-001", score=90),
            _make_assessment(correlation_id="corr-002", score=40),
        ]
        nfs = [_make_normalized(finding_id="nf-1"), _make_normalized(finding_id="nf-2")]
        cfs = [_make_correlated(correlation_id="corr-001"), _make_correlated(correlation_id="corr-002")]
        n1 = _make_attack_node("corr-001")
        n2 = _make_attack_node("corr-002")
        e = AttackEdge(source_id="node-corr-001", target_id="node-corr-002",
                        relationship="same_asset", confidence=0.8)
        p = AttackPath(path_id="path-1", nodes=(n1, n2), edges=(e,),
                       attack_score=70, confidence=0.8,
                       estimated_impact="High", attack_complexity="Moderate",
                       likelihood="Medium", reasoning="Two-step.",
                       recommendations=())
        ag = AttackGraph(paths=(p,), total_paths=1, highest_score=70,
                         average_score=70.0, metadata={})
        report = _BUILDER.build(nfs, cfs, efs, ras, ag)
        assert report.asset_summary.entries[0].highest_risk_score == 90


# ===========================================================================
# FindingSection
# ===========================================================================


class TestFindingSection:
    def test_entries_count(self) -> None:
        nfs, cfs, efs, ras, ag = _make_pipeline_single()
        report = _BUILDER.build(nfs, cfs, efs, ras, ag)
        assert report.finding_section.total_count == 1

    def test_ordered_by_severity(self) -> None:
        efs = [
            _make_enriched(correlation_id="corr-002", severity=Severity.MEDIUM),
            _make_enriched(correlation_id="corr-001", severity=Severity.CRITICAL),
        ]
        ras = [
            _make_assessment(correlation_id="corr-001", score=85, risk_level="Critical"),
            _make_assessment(correlation_id="corr-002", score=50, risk_level="Medium"),
        ]
        nfs = [_make_normalized(finding_id="nf-1"), _make_normalized(finding_id="nf-2")]
        cfs = [_make_correlated(correlation_id="corr-001"), _make_correlated(correlation_id="corr-002")]
        n1 = _make_attack_node("corr-001")
        n2 = _make_attack_node("corr-002")
        e = AttackEdge(source_id="node-corr-001", target_id="node-corr-002",
                        relationship="same_asset", confidence=0.8)
        p = AttackPath(path_id="path-1", nodes=(n1, n2), edges=(e,),
                       attack_score=71, confidence=0.8,
                       estimated_impact="High", attack_complexity="Moderate",
                       likelihood="Medium", reasoning="Two-step.",
                       recommendations=())
        ag = AttackGraph(paths=(p,), total_paths=1, highest_score=71,
                         average_score=71.0, metadata={})
        report = _BUILDER.build(nfs, cfs, efs, ras, ag)
        assert report.finding_section.entries[0].severity == "CRITICAL"
        assert report.finding_section.entries[1].severity == "MEDIUM"

    def test_severity_breakdown(self) -> None:
        nfs, cfs, efs, ras, ag = _make_pipeline_single()
        report = _BUILDER.build(nfs, cfs, efs, ras, ag)
        assert report.finding_section.severity_breakdown.get("HIGH") == 1


# ===========================================================================
# AttackPathSection
# ===========================================================================


class TestAttackPathSection:
    def test_passes_attack_graph(self) -> None:
        nfs, cfs, efs, ras, _ag = _make_pipeline_single()
        ag2 = _make_attack_graph(highest_score=75)
        report = _BUILDER.build(nfs, cfs, efs, ras, ag2)
        assert report.attack_path_section.total_paths == 1
        assert report.attack_path_section.highest_score == 75


# ===========================================================================
# RecommendationSection
# ===========================================================================


class TestRecommendationSection:
    def test_includes_findings_with_recs(self) -> None:
        nfs, cfs, efs, ras, ag = _make_pipeline_single()
        report = _BUILDER.build(nfs, cfs, efs, ras, ag)
        assert report.recommendation_section.total_recommendations == 1

    def test_excludes_findings_without_recs(self) -> None:
        ef = _make_enriched(correlation_id="corr-001", recommendations=())
        ra = _make_assessment(correlation_id="corr-001")
        nf = _make_normalized(finding_id="nf-1")
        cf = _make_correlated(correlation_id="corr-001")
        ag = _make_attack_graph()
        report = _BUILDER.build([nf], [cf], [ef], [ra], ag)
        assert report.recommendation_section.total_recommendations == 0

    def test_ordered_by_risk_score(self) -> None:
        efs = [
            _make_enriched(correlation_id="corr-001", title="Low Risk",
                           recommendations=("Fix A",)),
            _make_enriched(correlation_id="corr-002", title="High Risk",
                           recommendations=("Fix B",)),
        ]
        ras = [
            _make_assessment(correlation_id="corr-001", score=30, risk_level="Low"),
            _make_assessment(correlation_id="corr-002", score=90, risk_level="Critical"),
        ]
        nfs = [_make_normalized(finding_id="nf-1"), _make_normalized(finding_id="nf-2")]
        cfs = [_make_correlated(correlation_id="corr-001"), _make_correlated(correlation_id="corr-002")]
        n1 = _make_attack_node("corr-001")
        n2 = _make_attack_node("corr-002")
        e = AttackEdge(source_id="node-corr-001", target_id="node-corr-002",
                        relationship="same_asset", confidence=0.8)
        p = AttackPath(path_id="path-1", nodes=(n1, n2), edges=(e,),
                       attack_score=66, confidence=0.8,
                       estimated_impact="High", attack_complexity="Moderate",
                       likelihood="Medium", reasoning="Two-step.",
                       recommendations=())
        ag = AttackGraph(paths=(p,), total_paths=1, highest_score=66,
                         average_score=66.0, metadata={})
        report = _BUILDER.build(nfs, cfs, efs, ras, ag)
        entries = report.recommendation_section.entries
        assert entries[0].finding_title == "High Risk"
        assert entries[1].finding_title == "Low Risk"

    def test_total_recommendations_count(self) -> None:
        ef = _make_enriched(correlation_id="corr-001",
                            recommendations=("Fix A", "Fix B"))
        ra = _make_assessment(correlation_id="corr-001")
        nf = _make_normalized(finding_id="nf-1")
        cf = _make_correlated(correlation_id="corr-001")
        ag = _make_attack_graph()
        report = _BUILDER.build([nf], [cf], [ef], [ra], ag)
        assert report.recommendation_section.total_recommendations == 2


# ===========================================================================
# Appendix
# ===========================================================================


class TestAppendix:
    def test_scanner_versions(self) -> None:
        nfs = [
            _make_normalized(finding_id="nf-1", scanner_id="nuclei", scanner_version="3.2.1"),
            _make_normalized(finding_id="nf-2", scanner_id="nmap", scanner_version="7.95"),
        ]
        cfs = [_make_correlated(correlation_id="corr-001"), _make_correlated(correlation_id="corr-002")]
        efs = [_make_enriched(correlation_id="corr-001"), _make_enriched(correlation_id="corr-002")]
        ras = [_make_assessment(correlation_id="corr-001"), _make_assessment(correlation_id="corr-002")]
        n1 = _make_attack_node("corr-001")
        n2 = _make_attack_node("corr-002")
        e = AttackEdge(source_id="node-corr-001", target_id="node-corr-002",
                        relationship="same_asset", confidence=0.8)
        p = AttackPath(path_id="path-1", nodes=(n1, n2), edges=(e,),
                       attack_score=68, confidence=0.8,
                       estimated_impact="High", attack_complexity="Moderate",
                       likelihood="Medium", reasoning="Two-step.",
                       recommendations=())
        ag = AttackGraph(paths=(p,), total_paths=1, highest_score=68,
                         average_score=68.0, metadata={})
        report = _BUILDER.build(nfs, cfs, efs, ras, ag)
        versions = report.appendix.scanner_versions
        assert versions.get("nuclei") == "3.2.1"
        assert versions.get("nmap") == "7.95"

    def test_total_plugins(self) -> None:
        nfs = [
            _make_normalized(finding_id="nf-1", scanner_id="nuclei"),
            _make_normalized(finding_id="nf-2", scanner_id="nmap"),
        ]
        cfs = [_make_correlated(correlation_id="corr-001"), _make_correlated(correlation_id="corr-002")]
        efs = [_make_enriched(correlation_id="corr-001"), _make_enriched(correlation_id="corr-002")]
        ras = [_make_assessment(correlation_id="corr-001"), _make_assessment(correlation_id="corr-002")]
        n1 = _make_attack_node("corr-001")
        n2 = _make_attack_node("corr-002")
        e = AttackEdge(source_id="node-corr-001", target_id="node-corr-002",
                        relationship="same_asset", confidence=0.8)
        p = AttackPath(path_id="path-1", nodes=(n1, n2), edges=(e,),
                       attack_score=68, confidence=0.8,
                       estimated_impact="High", attack_complexity="Moderate",
                       likelihood="Medium", reasoning="Two-step.",
                       recommendations=())
        ag = AttackGraph(paths=(p,), total_paths=1, highest_score=68,
                         average_score=68.0, metadata={})
        report = _BUILDER.build(nfs, cfs, efs, ras, ag)
        assert report.appendix.total_plugins == 2

    def test_generated_by(self) -> None:
        nfs, cfs, efs, ras, ag = _make_pipeline_single()
        report = _BUILDER.build(nfs, cfs, efs, ras, ag)
        assert "KingSec" in report.appendix.generated_by


# ===========================================================================
# Deterministic ordering
# ===========================================================================


class TestDeterministicOrdering:
    def test_same_input_same_output(self) -> None:
        nfs, cfs, efs, ras, ag = _make_pipeline_single()
        r1 = _BUILDER.build(nfs, cfs, efs, ras, ag)
        r2 = _BUILDER.build(nfs, cfs, efs, ras, ag)
        assert r1.executive_summary == r2.executive_summary
        assert r1.technical_summary == r2.technical_summary
        assert r1.risk_summary == r2.risk_summary

    def test_finding_order_stable(self) -> None:
        efs = [
            _make_enriched(correlation_id="corr-002", severity=Severity.MEDIUM),
            _make_enriched(correlation_id="corr-001", severity=Severity.CRITICAL),
        ]
        ras = [
            _make_assessment(correlation_id="corr-001", score=85, risk_level="Critical"),
            _make_assessment(correlation_id="corr-002", score=50, risk_level="Medium"),
        ]
        nfs = [_make_normalized(finding_id="nf-1"), _make_normalized(finding_id="nf-2")]
        cfs = [_make_correlated(correlation_id="corr-001"), _make_correlated(correlation_id="corr-002")]
        n1 = _make_attack_node("corr-001")
        n2 = _make_attack_node("corr-002")
        e = AttackEdge(source_id="node-corr-001", target_id="node-corr-002",
                        relationship="same_asset", confidence=0.8)
        p = AttackPath(path_id="path-1", nodes=(n1, n2), edges=(e,),
                       attack_score=71, confidence=0.8,
                       estimated_impact="High", attack_complexity="Moderate",
                       likelihood="Medium", reasoning="Two-step.",
                       recommendations=())
        ag = AttackGraph(paths=(p,), total_paths=1, highest_score=71,
                         average_score=71.0, metadata={})
        r1 = _BUILDER.build(nfs, cfs, efs, ras, ag)
        r2 = _BUILDER.build(nfs, cfs, efs, ras, ag)
        for e1, e2 in zip(r1.finding_section.entries, r2.finding_section.entries, strict=False):
            assert e1.correlation_id == e2.correlation_id


# ===========================================================================
# Immutability / no mutation
# ===========================================================================


class TestImmutability:
    def test_builder_does_not_mutate_inputs(self) -> None:
        nfs, cfs, efs, ras, ag = _make_pipeline_single()
        nfs_copy = list(nfs)
        cfs_copy = list(cfs)
        efs_copy = list(efs)
        ras_copy = list(ras)
        _BUILDER.build(nfs, cfs, efs, ras, ag)
        assert nfs == nfs_copy
        assert cfs == cfs_copy
        assert efs == efs_copy
        assert ras == ras_copy


# ===========================================================================
# Edge cases
# ===========================================================================


class TestEdgeCases:
    def test_finding_without_risk_assessment(self) -> None:
        ef = _make_enriched(correlation_id="corr-001")
        nf = _make_normalized(finding_id="nf-1")
        cf = _make_correlated(correlation_id="corr-001")
        ag = _make_attack_graph()
        report = _BUILDER.build([nf], [cf], [ef], [], ag)
        assert report.executive_summary.total_risk_assessments == 0

    def test_finding_without_enrichment(self) -> None:
        ra = _make_assessment(correlation_id="corr-001")
        nf = _make_normalized(finding_id="nf-1")
        cf = _make_correlated(correlation_id="corr-001")
        n1 = _make_attack_node("corr-001")
        p = AttackPath(path_id="path-1", nodes=(n1,), edges=(),
                       attack_score=75, confidence=0.35,
                       estimated_impact="High", attack_complexity="Simple",
                       likelihood="Medium", reasoning="Single.",
                       recommendations=())
        ag = AttackGraph(paths=(p,), total_paths=1, highest_score=75,
                         average_score=75.0, metadata={})
        report = _BUILDER.build([nf], [cf], [], [ra], ag)
        assert report.executive_summary.total_enriched == 0

    def test_multiple_assets_same_finding(self) -> None:
        ef = _make_enriched(correlation_id="corr-001",
                            affected_assets=("10.0.0.1", "10.0.0.2"))
        ra = _make_assessment(correlation_id="corr-001", score=80)
        nf = _make_normalized(finding_id="nf-1")
        cf = _make_correlated(correlation_id="corr-001")
        ag = _make_attack_graph(highest_score=80)
        report = _BUILDER.build([nf], [cf], [ef], [ra], ag)
        assert report.executive_summary.total_assets == 2
        assert report.asset_summary.total_assets == 2

    def test_no_recommendations_in_any_finding(self) -> None:
        ef = _make_enriched(correlation_id="corr-001", recommendations=())
        ra = _make_assessment(correlation_id="corr-001")
        nf = _make_normalized(finding_id="nf-1")
        cf = _make_correlated(correlation_id="corr-001")
        ag = _make_attack_graph()
        report = _BUILDER.build([nf], [cf], [ef], [ra], ag)
        assert report.recommendation_section.total_recommendations == 0
        assert report.recommendation_section.entries == ()

    def test_attack_graph_preserved(self) -> None:
        nfs, cfs, efs, ras, ag = _make_pipeline_single()
        report = _BUILDER.build(nfs, cfs, efs, ras, ag)
        assert report.attack_path_section.graph is ag
