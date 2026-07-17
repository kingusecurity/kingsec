"""Executive Summary Generator: comprehensive tests."""

from __future__ import annotations

from datetime import datetime, timezone

import pytest

from kingsec.application.attack_path import (
    AttackEdge, AttackGraph, AttackNode, AttackPath,
)
from kingsec.application.enrichment import EnrichedFinding
from kingsec.application.executive_summary import (
    ExecutiveSummary, ExecutiveSummaryGenerator,
)
from kingsec.application.risk import RiskAssessment, RiskFactor
from kingsec.domain import Severity

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

_GENERATOR = ExecutiveSummaryGenerator()
_NOW = datetime(2026, 7, 17, tzinfo=timezone.utc)


def _make_factor(name: str = "severity", contribution: int = 22) -> RiskFactor:
    return RiskFactor(
        name=name, weight=30, contribution=contribution,
        description=f"{name} contributed {contribution}",
    )


def _make_assessment(
    correlation_id: str = "corr-001",
    score: int = 75,
    risk_level: str = "High",
) -> RiskAssessment:
    return RiskAssessment(
        correlation_id=correlation_id,
        score=score,
        risk_level=risk_level,
        priority=risk_level,
        reasoning=f"Score {score}/100",
        factors=(_make_factor("severity", min(score, 30)),),
    )


def _make_enriched(
    correlation_id: str = "corr-001",
    severity: Severity = Severity.HIGH,
    affected_assets: tuple[str, ...] = ("10.0.0.1",),
    scanner_sources: tuple[str, ...] = ("nuclei",),
    category: str = "vulnerability",
    recommendations: tuple[str, ...] = ("Patch OpenSSH",),
) -> EnrichedFinding:
    return EnrichedFinding(
        correlation_id=correlation_id,
        title=f"Finding {correlation_id}",
        description=f"Description for {correlation_id}",
        severity=severity,
        category=category,
        confidence=0.8,
        scanner_sources=scanner_sources,
        affected_assets=affected_assets,
        references=(),
        recommendations=recommendations,
        tags=(),
        software=(),
        service="SSH",
        protocol="TCP",
        port=22,
        technology=(),
        operating_system=None,
        attack_surface="Network Service",
        risk_factors=("Remote Code Execution",),
        business_impact="High",
        exploit_likelihood="Medium",
        remediation_complexity="Medium",
        priority="High",
        metadata={},
    )


def _make_node(correlation_id: str = "corr-001", score: int = 75) -> AttackNode:
    return AttackNode(
        node_id=f"node-{correlation_id}",
        correlation_id=correlation_id,
        title=f"Finding {correlation_id}",
        severity="HIGH",
        category="vulnerability",
        attack_surface="Network Service",
        service="SSH",
        port=22,
        protocol="TCP",
        asset="10.0.0.1",
        risk_score=score,
        risk_level="High",
    )


def _make_graph(
    total_paths: int = 1,
    highest_score: int = 75,
    node_score: int = 75,
) -> AttackGraph:
    n1 = _make_node("corr-001", node_score)
    p = AttackPath(
        path_id="path-1",
        nodes=(n1,),
        edges=(),
        attack_score=highest_score,
        confidence=0.35,
        estimated_impact="High",
        attack_complexity="Simple",
        likelihood="Medium",
        reasoning="Single step.",
        recommendations=(),
    )
    return AttackGraph(
        paths=(p,),
        total_paths=total_paths,
        highest_score=highest_score,
        average_score=float(highest_score),
        metadata={},
    )


def _make_graph_with_paths(
    count: int,
    highest_score: int = 75,
) -> AttackGraph:
    nodes = []
    for i in range(count):
        cid = f"corr-{i:04d}"
        node = _make_node(cid, highest_score if i == 0 else 50)
        nodes.append(node)
    edges = []
    for i in range(len(nodes) - 1):
        edges.append(AttackEdge(
            source_id=nodes[i].node_id,
            target_id=nodes[i + 1].node_id,
            relationship="same_asset",
            confidence=0.8,
        ))
    p = AttackPath(
        path_id="path-1",
        nodes=tuple(nodes),
        edges=tuple(edges),
        attack_score=highest_score,
        confidence=0.8,
        estimated_impact="High",
        attack_complexity="Moderate",
        likelihood="Medium",
        reasoning="Multi-step.",
        recommendations=(),
    )
    return AttackGraph(
        paths=(p,),
        total_paths=count,
        highest_score=highest_score,
        average_score=float(highest_score),
        metadata={},
    )


# ===========================================================================
# ExecutiveSummary dataclass
# ===========================================================================


class TestExecutiveSummaryDataclass:
    def test_creates_with_valid_data(self) -> None:
        es = ExecutiveSummary(
            overall_security_posture="Critical",
            total_findings=50,
            critical_count=5,
            high_count=10,
            medium_count=8,
            low_count=2,
            informational_count=25,
            overall_risk_level="Critical",
            highest_risk_score=95,
            average_risk_score=45.5,
            total_affected_assets=3,
            attack_path_count=2,
            highest_attack_path_score=85,
            top_security_concerns=("Critical RCE vulnerability",),
            key_observations=("Scan completed",),
            executive_recommendations=("Patch immediately",),
            prioritized_remediation_items=("Fix host 10.0.0.1",),
        )
        assert es.total_findings == 50
        assert es.highest_risk_score == 95

    def test_frozen(self) -> None:
        es = ExecutiveSummary(
            overall_security_posture="Good",
            total_findings=1,
            critical_count=0,
            high_count=0,
            medium_count=0,
            low_count=0,
            informational_count=1,
            overall_risk_level="Informational",
            highest_risk_score=0,
            average_risk_score=0.0,
            total_affected_assets=0,
            attack_path_count=0,
            highest_attack_path_score=0,
            top_security_concerns=("Nothing",),
            key_observations=("Clean",),
            executive_recommendations=("Keep monitoring",),
            prioritized_remediation_items=(),
        )
        with pytest.raises(AttributeError):
            es.total_findings = 100  # type: ignore[misc]

    def test_total_severe_property(self) -> None:
        es = ExecutiveSummary(
            overall_security_posture="Poor",
            total_findings=10,
            critical_count=3,
            high_count=4,
            medium_count=2,
            low_count=1,
            informational_count=0,
            overall_risk_level="High",
            highest_risk_score=85,
            average_risk_score=50.0,
            total_affected_assets=2,
            attack_path_count=1,
            highest_attack_path_score=80,
            top_security_concerns=(), key_observations=(),
            executive_recommendations=(), prioritized_remediation_items=(),
        )
        assert es.total_severe == 7

    def test_negative_total_raises(self) -> None:
        with pytest.raises(ValueError, match="total_findings"):
            ExecutiveSummary(
                overall_security_posture="Good", total_findings=-1,
                critical_count=0, high_count=0, medium_count=0,
                low_count=0, informational_count=0,
                overall_risk_level="Low", highest_risk_score=0,
                average_risk_score=0.0, total_affected_assets=0,
                attack_path_count=0, highest_attack_path_score=0,
                top_security_concerns=(), key_observations=(),
                executive_recommendations=(), prioritized_remediation_items=(),
            )

    def test_highest_score_out_of_range(self) -> None:
        with pytest.raises(ValueError, match="highest_risk_score"):
            ExecutiveSummary(
                overall_security_posture="Good", total_findings=0,
                critical_count=0, high_count=0, medium_count=0,
                low_count=0, informational_count=0,
                overall_risk_level="Low", highest_risk_score=200,
                average_risk_score=0.0, total_affected_assets=0,
                attack_path_count=0, highest_attack_path_score=0,
                top_security_concerns=(), key_observations=(),
                executive_recommendations=(), prioritized_remediation_items=(),
            )

    def test_attack_path_score_out_of_range(self) -> None:
        with pytest.raises(ValueError, match="highest_attack_path_score"):
            ExecutiveSummary(
                overall_security_posture="Good", total_findings=0,
                critical_count=0, high_count=0, medium_count=0,
                low_count=0, informational_count=0,
                overall_risk_level="Low", highest_risk_score=0,
                average_risk_score=0.0, total_affected_assets=0,
                attack_path_count=0, highest_attack_path_score=150,
                top_security_concerns=(), key_observations=(),
                executive_recommendations=(), prioritized_remediation_items=(),
            )

    def test_equality(self) -> None:
        kw = dict(
            overall_security_posture="Good", total_findings=1,
            critical_count=0, high_count=0, medium_count=0,
            low_count=1, informational_count=0,
            overall_risk_level="Low", highest_risk_score=10,
            average_risk_score=10.0, total_affected_assets=1,
            attack_path_count=0, highest_attack_path_score=0,
            top_security_concerns=("Low issue",),
            key_observations=("Minor",),
            executive_recommendations=("Monitor",),
            prioritized_remediation_items=("Check",),
        )
        assert ExecutiveSummary(**kw) == ExecutiveSummary(**kw)

    def test_hashable(self) -> None:
        es = ExecutiveSummary(
            overall_security_posture="Excellent", total_findings=0,
            critical_count=0, high_count=0, medium_count=0,
            low_count=0, informational_count=0,
            overall_risk_level="Informational", highest_risk_score=0,
            average_risk_score=0.0, total_affected_assets=0,
            attack_path_count=0, highest_attack_path_score=0,
            top_security_concerns=("None",),
            key_observations=("Clean",),
            executive_recommendations=("Keep up",),
            prioritized_remediation_items=(),
        )
        d = {es: "value"}
        assert d[es] == "value"


# ===========================================================================
# Generator — empty findings
# ===========================================================================


class TestGeneratorEmpty:
    def test_no_findings(self) -> None:
        es = _GENERATOR.generate([], _make_graph(0, 0, 0), [])
        assert es.total_findings == 0
        assert es.overall_risk_level == "Informational"
        assert es.overall_security_posture == "Excellent"

    def test_no_attack_paths(self) -> None:
        es = _GENERATOR.generate([], _make_graph(0, 0, 0), [])
        assert es.attack_path_count == 0

    def test_no_assets(self) -> None:
        es = _GENERATOR.generate([], _make_graph(0, 0, 0), [])
        assert es.total_affected_assets == 0

    def test_no_security_concerns(self) -> None:
        es = _GENERATOR.generate([], _make_graph(0, 0, 0), [])
        assert "No significant" in es.top_security_concerns[0]

    def test_no_observations(self) -> None:
        es = _GENERATOR.generate([], _make_graph(0, 0, 0), [])
        assert "No findings" in es.key_observations[0]


# ===========================================================================
# Generator — single finding
# ===========================================================================


class TestGeneratorSingle:
    def test_one_critical(self) -> None:
        ra = _make_assessment(score=95, risk_level="Critical")
        ef = _make_enriched(severity=Severity.CRITICAL)
        ag = _make_graph(highest_score=95, node_score=95)
        es = _GENERATOR.generate([ra], ag, [ef])
        assert es.total_findings == 1
        assert es.critical_count == 1
        assert es.highest_risk_score == 95
        assert es.overall_risk_level == "Critical"
        assert es.overall_security_posture == "Critical"

    def test_one_high(self) -> None:
        ra = _make_assessment(score=75, risk_level="High")
        ef = _make_enriched(severity=Severity.HIGH)
        ag = _make_graph(highest_score=75)
        es = _GENERATOR.generate([ra], ag, [ef])
        assert es.high_count == 1
        assert es.overall_risk_level == "High"
        assert es.overall_security_posture == "Poor"

    def test_one_low(self) -> None:
        ra = _make_assessment(score=20, risk_level="Low")
        ef = _make_enriched(severity=Severity.LOW)
        ag = _make_graph(highest_score=20, node_score=20)
        es = _GENERATOR.generate([ra], ag, [ef])
        assert es.low_count == 1
        assert es.overall_risk_level == "Low"
        assert es.overall_security_posture == "Good"


# ===========================================================================
# Generator — multiple severities
# ===========================================================================


class TestGeneratorMultipleSeverities:
    def test_critical_and_high(self) -> None:
        ras = [
            _make_assessment(correlation_id="corr-001", score=95, risk_level="Critical"),
            _make_assessment(correlation_id="corr-002", score=75, risk_level="High"),
        ]
        efs = [
            _make_enriched(correlation_id="corr-001", severity=Severity.CRITICAL),
            _make_enriched(correlation_id="corr-002", severity=Severity.HIGH),
        ]
        n1 = _make_node("corr-001", 95)
        n2 = _make_node("corr-002", 75)
        e = AttackEdge(source_id="node-corr-001", target_id="node-corr-002",
                        relationship="same_asset", confidence=0.8)
        p = AttackPath(path_id="path-1", nodes=(n1, n2), edges=(e,),
                       attack_score=87, confidence=0.8,
                       estimated_impact="Severe", attack_complexity="Moderate",
                       likelihood="High", reasoning="Multi-step.",
                       recommendations=())
        ag = AttackGraph(paths=(p,), total_paths=1, highest_score=87,
                         average_score=87.0, metadata={})
        es = _GENERATOR.generate(ras, ag, efs)
        assert es.critical_count == 1
        assert es.high_count == 1
        assert es.total_findings == 2

    def test_all_severities(self) -> None:
        ras = [
            _make_assessment(correlation_id="corr-c", score=95, risk_level="Critical"),
            _make_assessment(correlation_id="corr-h", score=75, risk_level="High"),
            _make_assessment(correlation_id="corr-m", score=50, risk_level="Medium"),
            _make_assessment(correlation_id="corr-l", score=15, risk_level="Low"),
            _make_assessment(correlation_id="corr-i", score=0, risk_level="Informational"),
        ]
        efs = [
            _make_enriched(correlation_id="corr-c", severity=Severity.CRITICAL),
            _make_enriched(correlation_id="corr-h", severity=Severity.HIGH),
            _make_enriched(correlation_id="corr-m", severity=Severity.MEDIUM),
            _make_enriched(correlation_id="corr-l", severity=Severity.LOW),
            _make_enriched(correlation_id="corr-i", severity=Severity.INFORMATIONAL),
        ]
        ag = _make_graph_with_paths(5, 95)
        es = _GENERATOR.generate(ras, ag, efs)
        assert es.critical_count == 1
        assert es.high_count == 1
        assert es.medium_count == 1
        assert es.low_count == 1
        assert es.informational_count == 1
        assert es.total_findings == 5


# ===========================================================================
# Generator — averages
# ===========================================================================


class TestGeneratorAverages:
    def test_average_risk_score(self) -> None:
        ras = [
            _make_assessment(correlation_id="corr-001", score=80),
            _make_assessment(correlation_id="corr-002", score=40),
        ]
        efs = [
            _make_enriched(correlation_id="corr-001"),
            _make_enriched(correlation_id="corr-002"),
        ]
        n1 = _make_node("corr-001", 80)
        n2 = _make_node("corr-002", 40)
        e = AttackEdge(source_id="node-corr-001", target_id="node-corr-002",
                        relationship="same_asset", confidence=0.8)
        p = AttackPath(path_id="path-1", nodes=(n1, n2), edges=(e,),
                       attack_score=64, confidence=0.8,
                       estimated_impact="High", attack_complexity="Moderate",
                       likelihood="Medium", reasoning="Multi-step.",
                       recommendations=())
        ag = AttackGraph(paths=(p,), total_paths=1, highest_score=64,
                         average_score=64.0, metadata={})
        es = _GENERATOR.generate(ras, ag, efs)
        assert es.average_risk_score == 60.0

    def test_highest_risk_score(self) -> None:
        ras = [
            _make_assessment(correlation_id="corr-001", score=90),
            _make_assessment(correlation_id="corr-002", score=30),
        ]
        efs = [
            _make_enriched(correlation_id="corr-001"),
            _make_enriched(correlation_id="corr-002"),
        ]
        n1 = _make_node("corr-001", 90)
        n2 = _make_node("corr-002", 30)
        e = AttackEdge(source_id="node-corr-001", target_id="node-corr-002",
                        relationship="same_asset", confidence=0.8)
        p = AttackPath(path_id="path-1", nodes=(n1, n2), edges=(e,),
                       attack_score=66, confidence=0.8,
                       estimated_impact="High", attack_complexity="Moderate",
                       likelihood="Medium", reasoning="Multi-step.",
                       recommendations=())
        ag = AttackGraph(paths=(p,), total_paths=1, highest_score=66,
                         average_score=66.0, metadata={})
        es = _GENERATOR.generate(ras, ag, efs)
        assert es.highest_risk_score == 90


# ===========================================================================
# Generator — attack paths
# ===========================================================================


class TestGeneratorAttackPaths:
    def test_single_path(self) -> None:
        ra = _make_assessment()
        ef = _make_enriched()
        ag = _make_graph(total_paths=1, highest_score=75)
        es = _GENERATOR.generate([ra], ag, [ef])
        assert es.attack_path_count == 1
        assert es.highest_attack_path_score == 75

    def test_multiple_paths(self) -> None:
        ra = _make_assessment()
        ef = _make_enriched()
        ag = _make_graph(total_paths=5, highest_score=90)
        es = _GENERATOR.generate([ra], ag, [ef])
        assert es.attack_path_count == 5
        assert es.highest_attack_path_score == 90


# ===========================================================================
# Generator — security concerns
# ===========================================================================


class TestGeneratorConcerns:
    def test_critical_concern(self) -> None:
        ra = _make_assessment(score=95, risk_level="Critical")
        ef = _make_enriched(severity=Severity.CRITICAL)
        ag = _make_graph(highest_score=95)
        es = _GENERATOR.generate([ra], ag, [ef])
        assert any("critical" in c.lower() for c in es.top_security_concerns)

    def test_high_concern(self) -> None:
        ra = _make_assessment(score=75, risk_level="High")
        ef = _make_enriched(severity=Severity.HIGH)
        ag = _make_graph(highest_score=75)
        es = _GENERATOR.generate([ra], ag, [ef])
        assert any("high-risk" in c.lower() for c in es.top_security_concerns)

    def test_path_concern(self) -> None:
        ra = _make_assessment(score=70, risk_level="High")
        ef = _make_enriched(severity=Severity.HIGH)
        ag = _make_graph(total_paths=2, highest_score=75)
        es = _GENERATOR.generate([ra], ag, [ef])
        assert any("attack path" in c.lower() for c in es.top_security_concerns)


# ===========================================================================
# Generator — recommendations
# ===========================================================================


class TestGeneratorRecommendations:
    def test_critical_recommendation(self) -> None:
        ra = _make_assessment(score=95, risk_level="Critical")
        ef = _make_enriched(severity=Severity.CRITICAL)
        ag = _make_graph(highest_score=95)
        es = _GENERATOR.generate([ra], ag, [ef])
        assert any("critical" in r.lower() for r in es.executive_recommendations)

    def test_multiple_recommendations(self) -> None:
        ras = [
            _make_assessment(correlation_id="corr-001", score=95, risk_level="Critical"),
            _make_assessment(correlation_id="corr-002", score=50, risk_level="Medium"),
        ]
        efs = [
            _make_enriched(correlation_id="corr-001", severity=Severity.CRITICAL),
            _make_enriched(correlation_id="corr-002", severity=Severity.MEDIUM),
        ]
        n1 = _make_node("corr-001", 95)
        n2 = _make_node("corr-002", 50)
        e = AttackEdge(source_id="node-corr-001", target_id="node-corr-002",
                        relationship="same_asset", confidence=0.8)
        p = AttackPath(path_id="path-1", nodes=(n1, n2), edges=(e,),
                       attack_score=77, confidence=0.8,
                       estimated_impact="Severe", attack_complexity="Moderate",
                       likelihood="High", reasoning="Multi-step.",
                       recommendations=())
        ag = AttackGraph(paths=(p,), total_paths=1, highest_score=77,
                         average_score=77.0, metadata={})
        es = _GENERATOR.generate(ras, ag, efs)
        assert len(es.executive_recommendations) >= 3

    def test_remediation_items_from_findings(self) -> None:
        ra = _make_assessment(correlation_id="corr-001", score=85)
        ef = _make_enriched(
            correlation_id="corr-001",
            severity=Severity.CRITICAL,
            recommendations=("Patch SSH", "Disable root login"),
        )
        ag = _make_graph(highest_score=85)
        es = _GENERATOR.generate([ra], ag, [ef])
        assert "Patch SSH" in es.prioritized_remediation_items
        assert "Disable root login" in es.prioritized_remediation_items

    def test_remediation_items_ordered_by_score(self) -> None:
        ras = [
            _make_assessment(correlation_id="corr-001", score=90),
            _make_assessment(correlation_id="corr-002", score=30),
        ]
        efs = [
            _make_enriched(correlation_id="corr-001", severity=Severity.CRITICAL,
                           recommendations=("Critical fix",)),
            _make_enriched(correlation_id="corr-002", severity=Severity.LOW,
                           recommendations=("Low fix",)),
        ]
        n1 = _make_node("corr-001", 90)
        n2 = _make_node("corr-002", 30)
        e = AttackEdge(source_id="node-corr-001", target_id="node-corr-002",
                        relationship="same_asset", confidence=0.8)
        p = AttackPath(path_id="path-1", nodes=(n1, n2), edges=(e,),
                       attack_score=66, confidence=0.8,
                       estimated_impact="High", attack_complexity="Moderate",
                       likelihood="Medium", reasoning="Multi-step.",
                       recommendations=())
        ag = AttackGraph(paths=(p,), total_paths=1, highest_score=66,
                         average_score=66.0, metadata={})
        es = _GENERATOR.generate(ras, ag, efs)
        assert es.prioritized_remediation_items[0] == "Critical fix"
        assert es.prioritized_remediation_items[1] == "Low fix"


# ===========================================================================
# Generator — observations
# ===========================================================================


class TestGeneratorObservations:
    def test_scanner_coverage(self) -> None:
        ef = _make_enriched(scanner_sources=("nuclei", "nmap"))
        ra = _make_assessment()
        ag = _make_graph()
        es = _GENERATOR.generate([ra], ag, [ef])
        assert any("2 scanner" in o for o in es.key_observations)

    def test_severe_ratio(self) -> None:
        ras = [
            _make_assessment(correlation_id="corr-001", score=95, risk_level="Critical"),
            _make_assessment(correlation_id="corr-002", score=75, risk_level="High"),
            _make_assessment(correlation_id="corr-003", score=50, risk_level="Medium"),
        ]
        efs = [
            _make_enriched(correlation_id="corr-001", severity=Severity.CRITICAL),
            _make_enriched(correlation_id="corr-002", severity=Severity.HIGH),
            _make_enriched(correlation_id="corr-003", severity=Severity.MEDIUM),
        ]
        n1 = _make_node("corr-001", 95)
        n2 = _make_node("corr-002", 75)
        n3 = _make_node("corr-003", 50)
        e1 = AttackEdge(source_id="node-corr-001", target_id="node-corr-002",
                         relationship="same_asset", confidence=0.8)
        e2 = AttackEdge(source_id="node-corr-002", target_id="node-corr-003",
                         relationship="same_asset", confidence=0.8)
        p = AttackPath(path_id="path-1", nodes=(n1, n2, n3), edges=(e1, e2),
                       attack_score=73, confidence=0.8,
                       estimated_impact="Severe", attack_complexity="Moderate",
                       likelihood="High", reasoning="Multi-step.",
                       recommendations=())
        ag = AttackGraph(paths=(p,), total_paths=1, highest_score=73,
                         average_score=73.0, metadata={})
        es = _GENERATOR.generate(ras, ag, efs)
        assert any("67%" in o for o in es.key_observations)

    def test_category_observation(self) -> None:
        ras = [
            _make_assessment(correlation_id="corr-001", score=75, risk_level="High"),
            _make_assessment(correlation_id="corr-002", score=50, risk_level="Medium"),
        ]
        efs = [
            _make_enriched(correlation_id="corr-001", severity=Severity.HIGH,
                           category="vulnerability"),
            _make_enriched(correlation_id="corr-002", severity=Severity.MEDIUM,
                           category="vulnerability"),
        ]
        n1 = _make_node("corr-001", 75)
        n2 = _make_node("corr-002", 50)
        e = AttackEdge(source_id="node-corr-001", target_id="node-corr-002",
                        relationship="same_asset", confidence=0.8)
        p = AttackPath(path_id="path-1", nodes=(n1, n2), edges=(e,),
                       attack_score=65, confidence=0.8,
                       estimated_impact="High", attack_complexity="Moderate",
                       likelihood="Medium", reasoning="Multi-step.",
                       recommendations=())
        ag = AttackGraph(paths=(p,), total_paths=1, highest_score=65,
                         average_score=65.0, metadata={})
        es = _GENERATOR.generate(ras, ag, efs)
        assert any("vulnerability" in o for o in es.key_observations)


# ===========================================================================
# Generator — deterministic ordering
# ===========================================================================


class TestGeneratorDeterministic:
    def test_same_input_same_output(self) -> None:
        ra = _make_assessment()
        ef = _make_enriched()
        ag = _make_graph()
        es1 = _GENERATOR.generate([ra], ag, [ef])
        es2 = _GENERATOR.generate([ra], ag, [ef])
        assert es1 == es2


# ===========================================================================
# Generator — immutability
# ===========================================================================


class TestGeneratorImmutability:
    def test_does_not_mutate_inputs(self) -> None:
        ras = [_make_assessment()]
        efs = [_make_enriched()]
        ag = _make_graph()
        ras_copy = list(ras)
        efs_copy = list(efs)
        _GENERATOR.generate(ras, ag, efs)
        assert ras == ras_copy
        assert efs == efs_copy


# ===========================================================================
# Edge cases
# ===========================================================================


class TestGeneratorEdgeCases:
    def test_no_assessments(self) -> None:
        ef = _make_enriched()
        ag = _make_graph(0, 0, 0)
        es = _GENERATOR.generate([], ag, [ef])
        assert es.total_findings == 1
        assert es.highest_risk_score == 0
        assert es.average_risk_score == 0.0

    def test_no_enriched(self) -> None:
        ra = _make_assessment()
        ag = _make_graph(0, 0, 0)
        es = _GENERATOR.generate([ra], ag, [])
        assert es.total_findings == 0
        assert es.total_affected_assets == 0

    def test_zero_scores(self) -> None:
        ra = _make_assessment(score=0, risk_level="Informational")
        ef = _make_enriched(severity=Severity.INFORMATIONAL)
        ag = _make_graph(0, 0, 0)
        es = _GENERATOR.generate([ra], ag, [ef])
        assert es.highest_risk_score == 0
        assert es.average_risk_score == 0.0

    def test_multiple_assets(self) -> None:
        ra = _make_assessment()
        ef = _make_enriched(affected_assets=("10.0.0.1", "10.0.0.2", "10.0.0.3"))
        ag = _make_graph()
        es = _GENERATOR.generate([ra], ag, [ef])
        assert es.total_affected_assets == 3

    def test_posture_degraded_by_attack_paths(self) -> None:
        ra = _make_assessment(score=70, risk_level="High")
        ef = _make_enriched(severity=Severity.HIGH)
        ag = _make_graph_with_paths(5, 70)
        es = _GENERATOR.generate([ra], ag, [ef])
        assert es.overall_security_posture == "Poor"

    def test_posture_high_without_degradation(self) -> None:
        ra = _make_assessment(score=70, risk_level="High")
        ef = _make_enriched(severity=Severity.HIGH)
        ag = _make_graph(1, 70)
        es = _GENERATOR.generate([ra], ag, [ef])
        assert es.overall_security_posture == "Poor"
