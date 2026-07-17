"""Report Domain Model: comprehensive tests."""

from __future__ import annotations

from datetime import datetime, timezone

import pytest

from kingsec.application.attack_path import (
    AttackEdge, AttackGraph, AttackNode, AttackPath,
)
from kingsec.application.correlation import CorrelatedFinding
from kingsec.application.enrichment import EnrichedFinding
from kingsec.application.normalization import NormalizedFinding
from kingsec.application.risk import RiskAssessment, RiskFactor
from kingsec.application.report import (
    Appendix, AssetEntry, AssetSummary, AttackPathSection,
    ExecutiveSummary, FindingEntry, FindingSection,
    RecommendationEntry, RecommendationSection, Report, RiskSummary,
    TechnicalSummary,
)
from kingsec.domain import Severity


# ===========================================================================
# Fixtures
# ===========================================================================

@pytest.fixture
def sample_finding_entry() -> FindingEntry:
    return FindingEntry(
        correlation_id="corr-001",
        title="SSH Vulnerability",
        severity="HIGH",
        category="vulnerability",
        confidence=0.8,
        scanner_sources=("nuclei", "nmap"),
        affected_assets=("10.0.0.1",),
        service="SSH",
        port=22,
        protocol="TCP",
        attack_surface="Network Service",
        risk_score=75,
        risk_level="High",
        priority="High",
    )


@pytest.fixture
def sample_asset_entry() -> AssetEntry:
    return AssetEntry(
        asset="10.0.0.1",
        finding_count=5,
        highest_risk_score=90,
        average_risk_score=55.5,
    )


@pytest.fixture
def sample_recommendation_entry() -> RecommendationEntry:
    return RecommendationEntry(
        finding_title="SSH Vulnerability",
        severity="HIGH",
        risk_score=75,
        correlation_id="corr-001",
        recommendations=("Update OpenSSH", "Disable root login"),
    )


@pytest.fixture
def sample_attack_graph() -> AttackGraph:
    n1 = AttackNode(
        node_id="node-corr-001", correlation_id="corr-001",
        title="SSH Vuln", severity="HIGH", category="vulnerability",
        attack_surface="Network Service", service="SSH",
        port=22, protocol="TCP", asset="10.0.0.1",
        risk_score=75, risk_level="High",
    )
    n2 = AttackNode(
        node_id="node-corr-002", correlation_id="corr-002",
        title="Web Vuln", severity="MEDIUM", category="vulnerability",
        attack_surface="Web Application", service="HTTP",
        port=80, protocol="TCP", asset="10.0.0.1",
        risk_score=50, risk_level="Medium",
    )
    e = AttackEdge(
        source_id="node-corr-001", target_id="node-corr-002",
        relationship="same_asset", confidence=0.8,
    )
    p = AttackPath(
        path_id="path-1", nodes=(n1, n2), edges=(e,),
        attack_score=65, confidence=0.8,
        estimated_impact="High", attack_complexity="Moderate",
        likelihood="Medium",
        reasoning="Two-step path.",
        recommendations=("Fix SSH", "Fix Web"),
    )
    return AttackGraph(
        paths=(p,), total_paths=1, highest_score=65,
        average_score=65.0, metadata={"total_assessments": "2"},
    )


# ===========================================================================
# ExecutiveSummary
# ===========================================================================


class TestExecutiveSummaryConstruction:
    def test_creates_with_valid_data(self) -> None:
        es = ExecutiveSummary(
            total_findings=100, total_correlated=50, total_enriched=50,
            total_risk_assessments=50, critical_count=10, high_count=20,
            medium_count=15, low_count=3, informational_count=2,
            top_risk_score=95, average_risk_score=45.5,
            total_assets=5, summary_text="10 critical findings identified.",
        )
        assert es.total_findings == 100
        assert es.top_risk_score == 95
        assert es.average_risk_score == 45.5

    def test_frozen(self) -> None:
        es = ExecutiveSummary(
            total_findings=10, total_correlated=5, total_enriched=5,
            total_risk_assessments=5, critical_count=1, high_count=2,
            medium_count=1, low_count=0, informational_count=1,
            top_risk_score=80, average_risk_score=40.0,
            total_assets=2, summary_text="Test summary.",
        )
        with pytest.raises(AttributeError):
            es.total_findings = 20  # type: ignore[misc]

    def test_top_risk_score_out_of_range(self) -> None:
        with pytest.raises(ValueError, match="top_risk_score"):
            ExecutiveSummary(
                total_findings=1, total_correlated=1, total_enriched=1,
                total_risk_assessments=1, critical_count=0, high_count=0,
                medium_count=0, low_count=0, informational_count=1,
                top_risk_score=150, average_risk_score=0.0,
                total_assets=1, summary_text="Bad score.",
            )

    def test_average_score_out_of_range(self) -> None:
        with pytest.raises(ValueError, match="average_risk_score"):
            ExecutiveSummary(
                total_findings=1, total_correlated=1, total_enriched=1,
                total_risk_assessments=1, critical_count=0, high_count=0,
                medium_count=0, low_count=0, informational_count=1,
                top_risk_score=0, average_risk_score=120.0,
                total_assets=1, summary_text="Bad avg.",
            )

    def test_empty_summary_text(self) -> None:
        with pytest.raises(ValueError, match="summary_text"):
            ExecutiveSummary(
                total_findings=1, total_correlated=1, total_enriched=1,
                total_risk_assessments=1, critical_count=0, high_count=0,
                medium_count=0, low_count=0, informational_count=1,
                top_risk_score=0, average_risk_score=0.0,
                total_assets=1, summary_text="",
            )

    def test_negative_counts(self) -> None:
        with pytest.raises(ValueError, match="total_findings"):
            ExecutiveSummary(
                total_findings=-1, total_correlated=0, total_enriched=0,
                total_risk_assessments=0, critical_count=0, high_count=0,
                medium_count=0, low_count=0, informational_count=0,
                top_risk_score=0, average_risk_score=0.0,
                total_assets=0, summary_text="Negative.",
            )

    def test_total_severe_property(self) -> None:
        es = ExecutiveSummary(
            total_findings=100, total_correlated=50, total_enriched=50,
            total_risk_assessments=50, critical_count=10, high_count=20,
            medium_count=15, low_count=3, informational_count=2,
            top_risk_score=95, average_risk_score=45.5,
            total_assets=5, summary_text="10 critical.",
        )
        assert es.total_severe == 30

    def test_equality(self) -> None:
        es1 = ExecutiveSummary(
            total_findings=10, total_correlated=5, total_enriched=5,
            total_risk_assessments=5, critical_count=1, high_count=2,
            medium_count=1, low_count=0, informational_count=1,
            top_risk_score=80, average_risk_score=40.0,
            total_assets=2, summary_text="Same.",
        )
        es2 = ExecutiveSummary(
            total_findings=10, total_correlated=5, total_enriched=5,
            total_risk_assessments=5, critical_count=1, high_count=2,
            medium_count=1, low_count=0, informational_count=1,
            top_risk_score=80, average_risk_score=40.0,
            total_assets=2, summary_text="Same.",
        )
        assert es1 == es2

    def test_inequality(self) -> None:
        es1 = ExecutiveSummary(
            total_findings=10, total_correlated=5, total_enriched=5,
            total_risk_assessments=5, critical_count=1, high_count=2,
            medium_count=1, low_count=0, informational_count=1,
            top_risk_score=80, average_risk_score=40.0,
            total_assets=2, summary_text="First.",
        )
        es2 = ExecutiveSummary(
            total_findings=10, total_correlated=5, total_enriched=5,
            total_risk_assessments=5, critical_count=1, high_count=2,
            medium_count=1, low_count=0, informational_count=1,
            top_risk_score=90, average_risk_score=40.0,
            total_assets=2, summary_text="Second.",
        )
        assert es1 != es2

    def test_hashable(self) -> None:
        es = ExecutiveSummary(
            total_findings=1, total_correlated=1, total_enriched=1,
            total_risk_assessments=1, critical_count=0, high_count=0,
            medium_count=0, low_count=0, informational_count=1,
            top_risk_score=0, average_risk_score=0.0,
            total_assets=0, summary_text="Hash.",
        )
        d = {es: "value"}
        assert d[es] == "value"


# ===========================================================================
# TechnicalSummary
# ===========================================================================


class TestTechnicalSummaryConstruction:
    def test_creates_with_valid_data(self) -> None:
        ts = TechnicalSummary(
            total_findings=100, total_correlations=50, total_enriched=50,
            total_risk_assessments=50,
            severity_breakdown={"HIGH": 30, "MEDIUM": 20},
            category_breakdown={"vulnerability": 40, "misconfiguration": 10},
            scanner_coverage={"nuclei": 50, "nmap": 30},
        )
        assert ts.total_findings == 100
        assert ts.scanner_coverage["nuclei"] == 50

    def test_frozen(self) -> None:
        ts = TechnicalSummary(
            total_findings=1, total_correlations=1, total_enriched=1,
            total_risk_assessments=1,
            severity_breakdown={"LOW": 1},
            category_breakdown={"info": 1},
            scanner_coverage={"manual": 1},
        )
        with pytest.raises(AttributeError):
            ts.total_findings = 5  # type: ignore[misc]

    def test_negative_total(self) -> None:
        with pytest.raises(ValueError, match="total_findings"):
            TechnicalSummary(
                total_findings=-1, total_correlations=0, total_enriched=0,
                total_risk_assessments=0,
                severity_breakdown={},
                category_breakdown={},
                scanner_coverage={},
            )

    def test_equality(self) -> None:
        kw = dict(
            total_findings=1, total_correlations=1, total_enriched=1,
            total_risk_assessments=1,
            severity_breakdown={"LOW": 1},
            category_breakdown={"info": 1},
            scanner_coverage={"x": 1},
        )
        assert TechnicalSummary(**kw) == TechnicalSummary(**kw)

    def test_hashable(self) -> None:
        ts = TechnicalSummary(
            total_findings=0, total_correlations=0, total_enriched=0,
            total_risk_assessments=0,
            severity_breakdown={},
            category_breakdown={},
            scanner_coverage={},
        )
        d = {ts: 1}
        assert d[ts] == 1


# ===========================================================================
# RiskSummary
# ===========================================================================


class TestRiskSummaryConstruction:
    def test_creates_with_valid_data(self) -> None:
        rs = RiskSummary(
            score_distribution={"Critical": 5, "High": 10, "Medium": 20},
            average_score=45.5, highest_score=95, lowest_score=10,
            top_risk_factors=("Remote Code Execution", "SQL Injection"),
        )
        assert rs.average_score == 45.5
        assert rs.highest_score == 95

    def test_frozen(self) -> None:
        rs = RiskSummary(
            score_distribution={"Low": 1},
            average_score=10.0, highest_score=10, lowest_score=10,
            top_risk_factors=(),
        )
        with pytest.raises(AttributeError):
            rs.average_score = 50.0  # type: ignore[misc]

    def test_empty_distribution_raises(self) -> None:
        with pytest.raises(ValueError, match="score_distribution"):
            RiskSummary(
                score_distribution={},
                average_score=0.0, highest_score=0, lowest_score=0,
                top_risk_factors=(),
            )

    def test_highest_score_out_of_range(self) -> None:
        with pytest.raises(ValueError, match="highest_score"):
            RiskSummary(
                score_distribution={"High": 1},
                average_score=0.0, highest_score=200, lowest_score=0,
                top_risk_factors=(),
            )

    def test_lowest_exceeds_highest(self) -> None:
        with pytest.raises(ValueError, match="lowest_score"):
            RiskSummary(
                score_distribution={"High": 1},
                average_score=50.0, highest_score=30, lowest_score=50,
                top_risk_factors=(),
            )

    def test_equality(self) -> None:
        kw = dict(
            score_distribution={"High": 1},
            average_score=50.0, highest_score=50, lowest_score=50,
            top_risk_factors=("XSS",),
        )
        assert RiskSummary(**kw) == RiskSummary(**kw)

    def test_hashable(self) -> None:
        rs = RiskSummary(
            score_distribution={"Low": 1},
            average_score=5.0, highest_score=5, lowest_score=5,
            top_risk_factors=(),
        )
        d = {rs: 1}
        assert d[rs] == 1


# ===========================================================================
# AssetEntry
# ===========================================================================


class TestAssetEntryConstruction:
    def test_creates_with_valid_data(self) -> None:
        ae = AssetEntry(
            asset="10.0.0.1",
            finding_count=5, highest_risk_score=90,
            average_risk_score=55.5,
        )
        assert ae.asset == "10.0.0.1"
        assert ae.highest_risk_score == 90

    def test_frozen(self) -> None:
        ae = AssetEntry(
            asset="10.0.0.1",
            finding_count=1, highest_risk_score=50,
            average_risk_score=50.0,
        )
        with pytest.raises(AttributeError):
            ae.asset = "10.0.0.2"  # type: ignore[misc]

    def test_empty_asset_raises(self) -> None:
        with pytest.raises(ValueError, match="asset"):
            AssetEntry(
                asset="",
                finding_count=1, highest_risk_score=50,
                average_risk_score=50.0,
            )

    def test_negative_finding_count(self) -> None:
        with pytest.raises(ValueError, match="finding_count"):
            AssetEntry(
                asset="10.0.0.1",
                finding_count=-1, highest_risk_score=0,
                average_risk_score=0.0,
            )

    def test_highest_score_out_of_range(self) -> None:
        with pytest.raises(ValueError, match="highest_risk_score"):
            AssetEntry(
                asset="10.0.0.1",
                finding_count=1, highest_risk_score=101,
                average_risk_score=0.0,
            )

    def test_average_score_out_of_range(self) -> None:
        with pytest.raises(ValueError, match="average_risk_score"):
            AssetEntry(
                asset="10.0.0.1",
                finding_count=1, highest_risk_score=0,
                average_risk_score=-1.0,
            )

    def test_equality(self) -> None:
        ae1 = AssetEntry(
            asset="10.0.0.1",
            finding_count=2, highest_risk_score=80,
            average_risk_score=60.0,
        )
        ae2 = AssetEntry(
            asset="10.0.0.1",
            finding_count=2, highest_risk_score=80,
            average_risk_score=60.0,
        )
        assert ae1 == ae2

    def test_hashable(self) -> None:
        ae = AssetEntry(
            asset="10.0.0.1",
            finding_count=1, highest_risk_score=50,
            average_risk_score=50.0,
        )
        d = {ae: "value"}
        assert d[ae] == "value"


# ===========================================================================
# AssetSummary
# ===========================================================================


class TestAssetSummaryConstruction:
    def test_creates_with_valid_data(self, sample_asset_entry: AssetEntry) -> None:
        a = AssetSummary(
            entries=(sample_asset_entry,),
            total_assets=1,
        )
        assert a.total_assets == 1
        assert len(a.entries) == 1

    def test_frozen(self, sample_asset_entry: AssetEntry) -> None:
        a = AssetSummary(entries=(sample_asset_entry,), total_assets=1)
        with pytest.raises(AttributeError):
            a.total_assets = 5  # type: ignore[misc]

    def test_empty_entries_raises(self) -> None:
        with pytest.raises(ValueError, match="entries"):
            AssetSummary(entries=(), total_assets=0)

    def test_total_findings_property(self, sample_asset_entry: AssetEntry) -> None:
        a = AssetSummary(entries=(sample_asset_entry,), total_assets=1)
        assert a.total_findings == sample_asset_entry.finding_count

    def test_equality(self, sample_asset_entry: AssetEntry) -> None:
        a1 = AssetSummary(entries=(sample_asset_entry,), total_assets=1)
        a2 = AssetSummary(entries=(sample_asset_entry,), total_assets=1)
        assert a1 == a2

    def test_hashable(self, sample_asset_entry: AssetEntry) -> None:
        a = AssetSummary(entries=(sample_asset_entry,), total_assets=1)
        d = {a: "v"}
        assert d[a] == "v"


# ===========================================================================
# FindingEntry
# ===========================================================================


class TestFindingEntryConstruction:
    def test_creates_with_valid_data(self, sample_finding_entry: FindingEntry) -> None:
        assert sample_finding_entry.correlation_id == "corr-001"
        assert sample_finding_entry.risk_score == 75

    def test_frozen(self, sample_finding_entry: FindingEntry) -> None:
        with pytest.raises(AttributeError):
            sample_finding_entry.title = "Changed"  # type: ignore[misc]

    def test_empty_correlation_id(self) -> None:
        with pytest.raises(ValueError, match="correlation_id"):
            FindingEntry(
                correlation_id="", title="T", severity="HIGH",
                category="vuln", confidence=0.5,
                scanner_sources=(), affected_assets=(),
                service=None, port=None, protocol=None,
                attack_surface=None, risk_score=0,
                risk_level="Low", priority="Low",
            )

    def test_empty_title(self) -> None:
        with pytest.raises(ValueError, match="title"):
            FindingEntry(
                correlation_id="c-1", title="", severity="HIGH",
                category="vuln", confidence=0.5,
                scanner_sources=(), affected_assets=(),
                service=None, port=None, protocol=None,
                attack_surface=None, risk_score=0,
                risk_level="Low", priority="Low",
            )

    def test_confidence_out_of_range(self) -> None:
        with pytest.raises(ValueError, match="confidence"):
            FindingEntry(
                correlation_id="c-1", title="T", severity="HIGH",
                category="vuln", confidence=1.5,
                scanner_sources=(), affected_assets=(),
                service=None, port=None, protocol=None,
                attack_surface=None, risk_score=0,
                risk_level="Low", priority="Low",
            )

    def test_risk_score_out_of_range(self) -> None:
        with pytest.raises(ValueError, match="risk_score"):
            FindingEntry(
                correlation_id="c-1", title="T", severity="HIGH",
                category="vuln", confidence=0.5,
                scanner_sources=(), affected_assets=(),
                service=None, port=None, protocol=None,
                attack_surface=None, risk_score=101,
                risk_level="Low", priority="Low",
            )

    def test_equality(self, sample_finding_entry: FindingEntry) -> None:
        fe2 = FindingEntry(
            correlation_id="corr-001",
            title="SSH Vulnerability",
            severity="HIGH",
            category="vulnerability",
            confidence=0.8,
            scanner_sources=("nuclei", "nmap"),
            affected_assets=("10.0.0.1",),
            service="SSH",
            port=22,
            protocol="TCP",
            attack_surface="Network Service",
            risk_score=75,
            risk_level="High",
            priority="High",
        )
        assert sample_finding_entry == fe2

    def test_hashable(self, sample_finding_entry: FindingEntry) -> None:
        d = {sample_finding_entry: "v"}
        assert d[sample_finding_entry] == "v"


# ===========================================================================
# FindingSection
# ===========================================================================


class TestFindingSectionConstruction:
    def test_creates_with_valid_data(self, sample_finding_entry: FindingEntry) -> None:
        fs = FindingSection(
            entries=(sample_finding_entry,),
            total_count=1,
            severity_breakdown={"HIGH": 1},
        )
        assert fs.total_count == 1
        assert fs.severity_breakdown["HIGH"] == 1

    def test_frozen(self, sample_finding_entry: FindingEntry) -> None:
        fs = FindingSection(
            entries=(sample_finding_entry,),
            total_count=1,
            severity_breakdown={"HIGH": 1},
        )
        with pytest.raises(AttributeError):
            fs.total_count = 5  # type: ignore[misc]

    def test_empty_entries_raises(self) -> None:
        with pytest.raises(ValueError, match="entries"):
            FindingSection(
                entries=(), total_count=0,
                severity_breakdown={},
            )

    def test_empty_breakdown_raises(self) -> None:
        fe = FindingEntry(
            correlation_id="c-1", title="T", severity="LOW",
            category="info", confidence=0.5,
            scanner_sources=(), affected_assets=(),
            service=None, port=None, protocol=None,
            attack_surface=None, risk_score=0,
            risk_level="Low", priority="Low",
        )
        with pytest.raises(ValueError, match="severity_breakdown"):
            FindingSection(
                entries=(fe,), total_count=1,
                severity_breakdown={},
            )

    def test_equality(self, sample_finding_entry: FindingEntry) -> None:
        fs1 = FindingSection(
            entries=(sample_finding_entry,),
            total_count=1,
            severity_breakdown={"HIGH": 1},
        )
        fs2 = FindingSection(
            entries=(sample_finding_entry,),
            total_count=1,
            severity_breakdown={"HIGH": 1},
        )
        assert fs1 == fs2

    def test_hashable(self, sample_finding_entry: FindingEntry) -> None:
        fs = FindingSection(
            entries=(sample_finding_entry,),
            total_count=1,
            severity_breakdown={"HIGH": 1},
        )
        d = {fs: "v"}
        assert d[fs] == "v"


# ===========================================================================
# AttackPathSection
# ===========================================================================


class TestAttackPathSectionConstruction:
    def test_creates_with_valid_data(self, sample_attack_graph: AttackGraph) -> None:
        a = AttackPathSection(
            total_paths=1, highest_score=65,
            average_score=65.0, graph=sample_attack_graph,
        )
        assert a.total_paths == 1
        assert a.average_score == 65.0

    def test_frozen(self, sample_attack_graph: AttackGraph) -> None:
        a = AttackPathSection(
            total_paths=1, highest_score=65,
            average_score=65.0, graph=sample_attack_graph,
        )
        with pytest.raises(AttributeError):
            a.total_paths = 5  # type: ignore[misc]

    def test_highest_score_out_of_range(self, sample_attack_graph: AttackGraph) -> None:
        with pytest.raises(ValueError, match="highest_score"):
            AttackPathSection(
                total_paths=1, highest_score=200,
                average_score=0.0, graph=sample_attack_graph,
            )

    def test_average_score_out_of_range(self, sample_attack_graph: AttackGraph) -> None:
        with pytest.raises(ValueError, match="average_score"):
            AttackPathSection(
                total_paths=1, highest_score=0,
                average_score=150.0, graph=sample_attack_graph,
            )

    def test_equality(self, sample_attack_graph: AttackGraph) -> None:
        a1 = AttackPathSection(
            total_paths=1, highest_score=65,
            average_score=65.0, graph=sample_attack_graph,
        )
        a2 = AttackPathSection(
            total_paths=1, highest_score=65,
            average_score=65.0, graph=sample_attack_graph,
        )
        assert a1 == a2

    def test_hashable(self, sample_attack_graph: AttackGraph) -> None:
        a = AttackPathSection(
            total_paths=1, highest_score=65,
            average_score=65.0, graph=sample_attack_graph,
        )
        d = {a: 1}
        assert d[a] == 1


# ===========================================================================
# RecommendationEntry
# ===========================================================================


class TestRecommendationEntryConstruction:
    def test_creates_with_valid_data(
        self, sample_recommendation_entry: RecommendationEntry,
    ) -> None:
        assert sample_recommendation_entry.finding_title == "SSH Vulnerability"
        assert len(sample_recommendation_entry.recommendations) == 2

    def test_frozen(self, sample_recommendation_entry: RecommendationEntry) -> None:
        with pytest.raises(AttributeError):
            sample_recommendation_entry.finding_title = "Changed"  # type: ignore[misc]

    def test_empty_title_raises(self) -> None:
        with pytest.raises(ValueError, match="finding_title"):
            RecommendationEntry(
                finding_title="", severity="HIGH", risk_score=50,
                correlation_id="c-1",
                recommendations=("Fix it",),
            )

    def test_empty_correlation_id_raises(self) -> None:
        with pytest.raises(ValueError, match="correlation_id"):
            RecommendationEntry(
                finding_title="XSS", severity="HIGH", risk_score=50,
                correlation_id="",
                recommendations=("Fix it",),
            )

    def test_risk_score_out_of_range(self) -> None:
        with pytest.raises(ValueError, match="risk_score"):
            RecommendationEntry(
                finding_title="XSS", severity="HIGH", risk_score=150,
                correlation_id="c-1",
                recommendations=("Fix it",),
            )

    def test_empty_recommendations_raises(self) -> None:
        with pytest.raises(ValueError, match="recommendations"):
            RecommendationEntry(
                finding_title="XSS", severity="HIGH", risk_score=50,
                correlation_id="c-1",
                recommendations=(),
            )

    def test_equality(self, sample_recommendation_entry: RecommendationEntry) -> None:
        r2 = RecommendationEntry(
            finding_title="SSH Vulnerability",
            severity="HIGH",
            risk_score=75,
            correlation_id="corr-001",
            recommendations=("Update OpenSSH", "Disable root login"),
        )
        assert sample_recommendation_entry == r2

    def test_hashable(self, sample_recommendation_entry: RecommendationEntry) -> None:
        d = {sample_recommendation_entry: 1}
        assert d[sample_recommendation_entry] == 1


# ===========================================================================
# RecommendationSection
# ===========================================================================


class TestRecommendationSectionConstruction:
    def test_creates_with_valid_data(
        self, sample_recommendation_entry: RecommendationEntry,
    ) -> None:
        rs = RecommendationSection(
            entries=(sample_recommendation_entry,),
            total_recommendations=2,
        )
        assert rs.total_recommendations == 2
        assert len(rs.entries) == 1

    def test_frozen(self, sample_recommendation_entry: RecommendationEntry) -> None:
        rs = RecommendationSection(
            entries=(sample_recommendation_entry,),
            total_recommendations=2,
        )
        with pytest.raises(AttributeError):
            rs.total_recommendations = 5  # type: ignore[misc]

    def test_empty_entries_raises(self) -> None:
        with pytest.raises(ValueError, match="entries"):
            RecommendationSection(entries=(), total_recommendations=0)

    def test_negative_total(self, sample_recommendation_entry: RecommendationEntry) -> None:
        with pytest.raises(ValueError, match="total_recommendations"):
            RecommendationSection(
                entries=(sample_recommendation_entry,),
                total_recommendations=-1,
            )

    def test_equality(self, sample_recommendation_entry: RecommendationEntry) -> None:
        rs1 = RecommendationSection(
            entries=(sample_recommendation_entry,),
            total_recommendations=2,
        )
        rs2 = RecommendationSection(
            entries=(sample_recommendation_entry,),
            total_recommendations=2,
        )
        assert rs1 == rs2

    def test_hashable(self, sample_recommendation_entry: RecommendationEntry) -> None:
        rs = RecommendationSection(
            entries=(sample_recommendation_entry,),
            total_recommendations=2,
        )
        d = {rs: "v"}
        assert d[rs] == "v"


# ===========================================================================
# Appendix
# ===========================================================================


class TestAppendixConstruction:
    def test_creates_with_valid_data(self) -> None:
        dt = datetime(2026, 7, 17, tzinfo=timezone.utc)
        a = Appendix(
            scanner_versions={"nuclei": "3.2.1", "nmap": "7.95"},
            total_plugins=2,
            generated_at=dt,
            generated_by="KingSec v1.0.0",
        )
        assert a.total_plugins == 2
        assert a.generated_by == "KingSec v1.0.0"

    def test_frozen(self) -> None:
        dt = datetime(2026, 1, 1, tzinfo=timezone.utc)
        a = Appendix(
            scanner_versions={"nuclei": "1.0"},
            total_plugins=1,
            generated_at=dt,
            generated_by="KingSec",
        )
        with pytest.raises(AttributeError):
            a.total_plugins = 5  # type: ignore[misc]

    def test_empty_versions_raises(self) -> None:
        with pytest.raises(ValueError, match="scanner_versions"):
            Appendix(
                scanner_versions={},
                total_plugins=0,
                generated_at=datetime.now(timezone.utc),
                generated_by="KingSec",
            )

    def test_negative_plugins(self) -> None:
        with pytest.raises(ValueError, match="total_plugins"):
            Appendix(
                scanner_versions={"nuclei": "1.0"},
                total_plugins=-1,
                generated_at=datetime.now(timezone.utc),
                generated_by="KingSec",
            )

    def test_empty_generated_by(self) -> None:
        with pytest.raises(ValueError, match="generated_by"):
            Appendix(
                scanner_versions={"nuclei": "1.0"},
                total_plugins=1,
                generated_at=datetime.now(timezone.utc),
                generated_by="",
            )

    def test_equality(self) -> None:
        dt = datetime(2026, 1, 1, tzinfo=timezone.utc)
        a1 = Appendix(
            scanner_versions={"nuclei": "1.0"},
            total_plugins=1,
            generated_at=dt,
            generated_by="KingSec",
        )
        a2 = Appendix(
            scanner_versions={"nuclei": "1.0"},
            total_plugins=1,
            generated_at=dt,
            generated_by="KingSec",
        )
        assert a1 == a2

    def test_hashable(self) -> None:
        dt = datetime(2026, 1, 1, tzinfo=timezone.utc)
        a = Appendix(
            scanner_versions={"nuclei": "1.0"},
            total_plugins=1,
            generated_at=dt,
            generated_by="KingSec",
        )
        d = {a: 1}
        assert d[a] == 1


# ===========================================================================
# Report (aggregate)
# ===========================================================================


class TestReportConstruction:
    def test_creates_with_valid_data(
        self, sample_finding_entry: FindingEntry,
        sample_asset_entry: AssetEntry,
        sample_recommendation_entry: RecommendationEntry,
        sample_attack_graph: AttackGraph,
    ) -> None:
        es = ExecutiveSummary(
            total_findings=50, total_correlated=25, total_enriched=25,
            total_risk_assessments=25, critical_count=5, high_count=10,
            medium_count=8, low_count=1, informational_count=1,
            top_risk_score=95, average_risk_score=45.5,
            total_assets=3, summary_text="5 critical findings.",
        )
        ts = TechnicalSummary(
            total_findings=50, total_correlations=25, total_enriched=25,
            total_risk_assessments=25,
            severity_breakdown={"HIGH": 15},
            category_breakdown={"vuln": 25},
            scanner_coverage={"nuclei": 25},
        )
        rs = RiskSummary(
            score_distribution={"Critical": 5},
            average_score=45.5, highest_score=95, lowest_score=10,
            top_risk_factors=("RCE",),
        )
        a = AssetSummary(entries=(sample_asset_entry,), total_assets=1)
        fs = FindingSection(
            entries=(sample_finding_entry,),
            total_count=1,
            severity_breakdown={"HIGH": 1},
        )
        ap = AttackPathSection(
            total_paths=1, highest_score=65,
            average_score=65.0, graph=sample_attack_graph,
        )
        recs = RecommendationSection(
            entries=(sample_recommendation_entry,),
            total_recommendations=2,
        )
        app = Appendix(
            scanner_versions={"nuclei": "3.2"},
            total_plugins=1,
            generated_at=datetime(2026, 7, 17, tzinfo=timezone.utc),
            generated_by="KingSec v1.0",
        )
        r = Report(
            report_id="rpt-001",
            title="Security Scan Report",
            created_at=datetime(2026, 7, 17, tzinfo=timezone.utc),
            executive_summary=es,
            technical_summary=ts,
            risk_summary=rs,
            asset_summary=a,
            finding_section=fs,
            attack_path_section=ap,
            recommendation_section=recs,
            appendix=app,
        )
        assert r.report_id == "rpt-001"
        assert r.title == "Security Scan Report"

    def test_frozen(
        self, sample_finding_entry: FindingEntry,
        sample_asset_entry: AssetEntry,
        sample_recommendation_entry: RecommendationEntry,
        sample_attack_graph: AttackGraph,
    ) -> None:
        es = ExecutiveSummary(
            total_findings=1, total_correlated=1, total_enriched=1,
            total_risk_assessments=1, critical_count=0, high_count=0,
            medium_count=0, low_count=0, informational_count=1,
            top_risk_score=0, average_risk_score=0.0,
            total_assets=0, summary_text="T.",
        )
        ts = TechnicalSummary(
            total_findings=1, total_correlations=1, total_enriched=1,
            total_risk_assessments=1,
            severity_breakdown={"LOW": 1},
            category_breakdown={"info": 1},
            scanner_coverage={"x": 1},
        )
        rs = RiskSummary(
            score_distribution={"Low": 1},
            average_score=0.0, highest_score=0, lowest_score=0,
            top_risk_factors=(),
        )
        a = AssetSummary(entries=(sample_asset_entry,), total_assets=1)
        fs = FindingSection(
            entries=(sample_finding_entry,),
            total_count=1,
            severity_breakdown={"HIGH": 1},
        )
        ap = AttackPathSection(
            total_paths=1, highest_score=65,
            average_score=65.0, graph=sample_attack_graph,
        )
        recs = RecommendationSection(
            entries=(sample_recommendation_entry,),
            total_recommendations=2,
        )
        app = Appendix(
            scanner_versions={"nuclei": "1.0"},
            total_plugins=1,
            generated_at=datetime(2026, 1, 1, tzinfo=timezone.utc),
            generated_by="KingSec",
        )
        r = Report(
            report_id="rpt-001",
            title="T",
            created_at=datetime(2026, 1, 1, tzinfo=timezone.utc),
            executive_summary=es,
            technical_summary=ts,
            risk_summary=rs,
            asset_summary=a,
            finding_section=fs,
            attack_path_section=ap,
            recommendation_section=recs,
            appendix=app,
        )
        with pytest.raises(AttributeError):
            r.title = "Changed"  # type: ignore[misc]

    def test_empty_report_id_raises(
        self, sample_finding_entry: FindingEntry,
        sample_asset_entry: AssetEntry,
        sample_recommendation_entry: RecommendationEntry,
        sample_attack_graph: AttackGraph,
    ) -> None:
        es = ExecutiveSummary(
            total_findings=1, total_correlated=1, total_enriched=1,
            total_risk_assessments=1, critical_count=0, high_count=0,
            medium_count=0, low_count=0, informational_count=1,
            top_risk_score=0, average_risk_score=0.0,
            total_assets=0, summary_text="T.",
        )
        ts = TechnicalSummary(
            total_findings=1, total_correlations=1, total_enriched=1,
            total_risk_assessments=1,
            severity_breakdown={"LOW": 1},
            category_breakdown={"info": 1},
            scanner_coverage={"x": 1},
        )
        rs = RiskSummary(
            score_distribution={"Low": 1},
            average_score=0.0, highest_score=0, lowest_score=0,
            top_risk_factors=(),
        )
        a = AssetSummary(entries=(sample_asset_entry,), total_assets=1)
        fs = FindingSection(
            entries=(sample_finding_entry,),
            total_count=1,
            severity_breakdown={"HIGH": 1},
        )
        ap = AttackPathSection(
            total_paths=1, highest_score=65,
            average_score=65.0, graph=sample_attack_graph,
        )
        recs = RecommendationSection(
            entries=(sample_recommendation_entry,),
            total_recommendations=2,
        )
        app = Appendix(
            scanner_versions={"nuclei": "1.0"},
            total_plugins=1,
            generated_at=datetime(2026, 1, 1, tzinfo=timezone.utc),
            generated_by="KingSec",
        )
        with pytest.raises(ValueError, match="report_id"):
            Report(
                report_id="",
                title="T",
                created_at=datetime(2026, 1, 1, tzinfo=timezone.utc),
                executive_summary=es,
                technical_summary=ts,
                risk_summary=rs,
                asset_summary=a,
                finding_section=fs,
                attack_path_section=ap,
                recommendation_section=recs,
                appendix=app,
            )

    def test_empty_title_raises(
        self, sample_finding_entry: FindingEntry,
        sample_asset_entry: AssetEntry,
        sample_recommendation_entry: RecommendationEntry,
        sample_attack_graph: AttackGraph,
    ) -> None:
        es = ExecutiveSummary(
            total_findings=1, total_correlated=1, total_enriched=1,
            total_risk_assessments=1, critical_count=0, high_count=0,
            medium_count=0, low_count=0, informational_count=1,
            top_risk_score=0, average_risk_score=0.0,
            total_assets=0, summary_text="T.",
        )
        ts = TechnicalSummary(
            total_findings=1, total_correlations=1, total_enriched=1,
            total_risk_assessments=1,
            severity_breakdown={"LOW": 1},
            category_breakdown={"info": 1},
            scanner_coverage={"x": 1},
        )
        rs = RiskSummary(
            score_distribution={"Low": 1},
            average_score=0.0, highest_score=0, lowest_score=0,
            top_risk_factors=(),
        )
        a = AssetSummary(entries=(sample_asset_entry,), total_assets=1)
        fs = FindingSection(
            entries=(sample_finding_entry,),
            total_count=1,
            severity_breakdown={"HIGH": 1},
        )
        ap = AttackPathSection(
            total_paths=1, highest_score=65,
            average_score=65.0, graph=sample_attack_graph,
        )
        recs = RecommendationSection(
            entries=(sample_recommendation_entry,),
            total_recommendations=2,
        )
        app = Appendix(
            scanner_versions={"nuclei": "1.0"},
            total_plugins=1,
            generated_at=datetime(2026, 1, 1, tzinfo=timezone.utc),
            generated_by="KingSec",
        )
        with pytest.raises(ValueError, match="title"):
            Report(
                report_id="rpt-001",
                title="",
                created_at=datetime(2026, 1, 1, tzinfo=timezone.utc),
                executive_summary=es,
                technical_summary=ts,
                risk_summary=rs,
                asset_summary=a,
                finding_section=fs,
                attack_path_section=ap,
                recommendation_section=recs,
                appendix=app,
            )

    def test_total_sections_property(
        self, sample_finding_entry: FindingEntry,
        sample_asset_entry: AssetEntry,
        sample_recommendation_entry: RecommendationEntry,
        sample_attack_graph: AttackGraph,
    ) -> None:
        es = ExecutiveSummary(
            total_findings=1, total_correlated=1, total_enriched=1,
            total_risk_assessments=1, critical_count=0, high_count=0,
            medium_count=0, low_count=0, informational_count=1,
            top_risk_score=0, average_risk_score=0.0,
            total_assets=0, summary_text="T.",
        )
        ts = TechnicalSummary(
            total_findings=1, total_correlations=1, total_enriched=1,
            total_risk_assessments=1,
            severity_breakdown={"LOW": 1},
            category_breakdown={"info": 1},
            scanner_coverage={"x": 1},
        )
        rs = RiskSummary(
            score_distribution={"Low": 1},
            average_score=0.0, highest_score=0, lowest_score=0,
            top_risk_factors=(),
        )
        a = AssetSummary(entries=(sample_asset_entry,), total_assets=1)
        fs = FindingSection(
            entries=(sample_finding_entry,),
            total_count=1,
            severity_breakdown={"HIGH": 1},
        )
        ap = AttackPathSection(
            total_paths=1, highest_score=65,
            average_score=65.0, graph=sample_attack_graph,
        )
        recs = RecommendationSection(
            entries=(sample_recommendation_entry,),
            total_recommendations=2,
        )
        app = Appendix(
            scanner_versions={"nuclei": "1.0"},
            total_plugins=1,
            generated_at=datetime(2026, 1, 1, tzinfo=timezone.utc),
            generated_by="KingSec",
        )
        r = Report(
            report_id="rpt-001",
            title="T",
            created_at=datetime(2026, 1, 1, tzinfo=timezone.utc),
            executive_summary=es,
            technical_summary=ts,
            risk_summary=rs,
            asset_summary=a,
            finding_section=fs,
            attack_path_section=ap,
            recommendation_section=recs,
            appendix=app,
        )
        assert r.total_sections == 7

    def test_equality(
        self, sample_finding_entry: FindingEntry,
        sample_asset_entry: AssetEntry,
        sample_recommendation_entry: RecommendationEntry,
        sample_attack_graph: AttackGraph,
    ) -> None:
        dt = datetime(2026, 1, 1, tzinfo=timezone.utc)
        base_kw = dict(
            report_id="rpt-001",
            title="T",
            created_at=dt,
            executive_summary=ExecutiveSummary(
                total_findings=1, total_correlated=1, total_enriched=1,
                total_risk_assessments=1, critical_count=0, high_count=0,
                medium_count=0, low_count=0, informational_count=1,
                top_risk_score=0, average_risk_score=0.0,
                total_assets=0, summary_text="T.",
            ),
            technical_summary=TechnicalSummary(
                total_findings=1, total_correlations=1, total_enriched=1,
                total_risk_assessments=1,
                severity_breakdown={"LOW": 1},
                category_breakdown={"info": 1},
                scanner_coverage={"x": 1},
            ),
            risk_summary=RiskSummary(
                score_distribution={"Low": 1},
                average_score=0.0, highest_score=0, lowest_score=0,
                top_risk_factors=(),
            ),
            asset_summary=AssetSummary(
                entries=(sample_asset_entry,), total_assets=1,
            ),
            finding_section=FindingSection(
                entries=(sample_finding_entry,),
                total_count=1,
                severity_breakdown={"HIGH": 1},
            ),
            attack_path_section=AttackPathSection(
                total_paths=1, highest_score=65,
                average_score=65.0, graph=sample_attack_graph,
            ),
            recommendation_section=RecommendationSection(
                entries=(sample_recommendation_entry,),
                total_recommendations=2,
            ),
            appendix=Appendix(
                scanner_versions={"nuclei": "1.0"},
                total_plugins=1,
                generated_at=dt,
                generated_by="KingSec",
            ),
        )
        assert Report(**base_kw) == Report(**base_kw)

    def test_hashable(
        self, sample_finding_entry: FindingEntry,
        sample_asset_entry: AssetEntry,
        sample_recommendation_entry: RecommendationEntry,
        sample_attack_graph: AttackGraph,
    ) -> None:
        dt = datetime(2026, 1, 1, tzinfo=timezone.utc)
        r = Report(
            report_id="rpt-001",
            title="T",
            created_at=dt,
            executive_summary=ExecutiveSummary(
                total_findings=1, total_correlated=1, total_enriched=1,
                total_risk_assessments=1, critical_count=0, high_count=0,
                medium_count=0, low_count=0, informational_count=1,
                top_risk_score=0, average_risk_score=0.0,
                total_assets=0, summary_text="T.",
            ),
            technical_summary=TechnicalSummary(
                total_findings=1, total_correlations=1, total_enriched=1,
                total_risk_assessments=1,
                severity_breakdown={"LOW": 1},
                category_breakdown={"info": 1},
                scanner_coverage={"x": 1},
            ),
            risk_summary=RiskSummary(
                score_distribution={"Low": 1},
                average_score=0.0, highest_score=0, lowest_score=0,
                top_risk_factors=(),
            ),
            asset_summary=AssetSummary(
                entries=(sample_asset_entry,), total_assets=1,
            ),
            finding_section=FindingSection(
                entries=(sample_finding_entry,),
                total_count=1,
                severity_breakdown={"HIGH": 1},
            ),
            attack_path_section=AttackPathSection(
                total_paths=1, highest_score=65,
                average_score=65.0, graph=sample_attack_graph,
            ),
            recommendation_section=RecommendationSection(
                entries=(sample_recommendation_entry,),
                total_recommendations=2,
            ),
            appendix=Appendix(
                scanner_versions={"nuclei": "1.0"},
                total_plugins=1,
                generated_at=dt,
                generated_by="KingSec",
            ),
        )
        d = {r: 1}
        assert d[r] == 1
