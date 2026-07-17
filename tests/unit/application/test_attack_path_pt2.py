"""Part 2: test classes."""
# flake8: noqa: F811

import pytest
from kingsec.application.attack_path import (
    AttackEdge, AttackGraph, AttackNode, AttackPath, AttackPathAnalyzer,
)
from kingsec.application.enrichment import EnrichedFinding
from kingsec.application.risk import RiskAssessment, RiskFactor
from kingsec.domain import Severity

from test_attack_path import _ENGINE, _make_assessment, _make_finding


# ===========================================================================
# AttackNode construction
# ===========================================================================


class TestAttackNode:
    def test_creates_with_valid_data(self) -> None:
        n = AttackNode(
            node_id="node-1", correlation_id="corr-001",
            title="SSH Vuln", severity="HIGH", category="vulnerability",
            attack_surface="Network Service", service="SSH",
            port=22, protocol="TCP", asset="10.0.0.1",
            risk_score=60, risk_level="High",
        )
        assert n.node_id == "node-1"
        assert n.risk_score == 60
        assert n.severity == "HIGH"

    def test_frozen_immutable(self) -> None:
        n = AttackNode(
            node_id="node-1", correlation_id="corr-001",
            title="T", severity="LOW", category="info",
            attack_surface=None, service=None,
            port=None, protocol=None, asset=None,
            risk_score=10, risk_level="Low",
        )
        with pytest.raises(AttributeError):
            n.title = "changed"  # type: ignore[misc]

    def test_empty_node_id_raises(self) -> None:
        with pytest.raises(ValueError, match="node_id"):
            AttackNode(
                node_id="", correlation_id="corr-001",
                title="T", severity="LOW", category="info",
                attack_surface=None, service=None,
                port=None, protocol=None, asset=None,
                risk_score=10, risk_level="Low",
            )

    def test_empty_correlation_id_raises(self) -> None:
        with pytest.raises(ValueError, match="correlation_id"):
            AttackNode(
                node_id="node-1", correlation_id="",
                title="T", severity="LOW", category="info",
                attack_surface=None, service=None,
                port=None, protocol=None, asset=None,
                risk_score=10, risk_level="Low",
            )

    def test_nullable_fields(self) -> None:
        n = AttackNode(
            node_id="node-1", correlation_id="corr-001",
            title="T", severity="LOW", category="info",
            attack_surface=None, service=None,
            port=None, protocol=None, asset=None,
            risk_score=10, risk_level="Low",
        )
        assert n.attack_surface is None
        assert n.service is None


class TestAttackEdge:
    def test_creates_with_valid_data(self) -> None:
        e = AttackEdge(
            source_id="node-1", target_id="node-2",
            relationship="same_asset", confidence=0.8,
        )
        assert e.source_id == "node-1"
        assert e.target_id == "node-2"
        assert e.confidence == 0.8

    def test_frozen_immutable(self) -> None:
        e = AttackEdge(
            source_id="node-1", target_id="node-2",
            relationship="same_asset", confidence=0.8,
        )
        with pytest.raises(AttributeError):
            e.confidence = 0.5  # type: ignore[misc]

    def test_empty_source_raises(self) -> None:
        with pytest.raises(ValueError, match="source_id"):
            AttackEdge(
                source_id="", target_id="node-2",
                relationship="same_asset", confidence=0.8,
            )

    def test_self_loop_raises(self) -> None:
        with pytest.raises(ValueError, match="source and target"):
            AttackEdge(
                source_id="node-1", target_id="node-1",
                relationship="same_asset", confidence=0.8,
            )

    def test_confidence_out_of_range_raises(self) -> None:
        with pytest.raises(ValueError, match="confidence"):
            AttackEdge(
                source_id="node-1", target_id="node-2",
                relationship="same_asset", confidence=1.5,
            )


class TestAttackPath:
    def test_creates(self) -> None:
        n = AttackNode(
            node_id="node-1", correlation_id="corr-001",
            title="T", severity="HIGH", category="vuln",
            attack_surface="Web", service="HTTP",
            port=80, protocol="TCP", asset="10.0.0.1",
            risk_score=60, risk_level="High",
        )
        p = AttackPath(
            path_id="path-1", nodes=(n,), edges=(),
            attack_score=60, confidence=0.35,
            estimated_impact="High", attack_complexity="Simple",
            likelihood="Medium", reasoning="Single step.",
            recommendations=("Fix it",),
        )
        assert p.path_id == "path-1"
        assert p.attack_score == 60

    def test_frozen(self) -> None:
        n = AttackNode(
            node_id="node-1", correlation_id="corr-001",
            title="T", severity="LOW", category="info",
            attack_surface=None, service=None,
            port=None, protocol=None, asset=None,
            risk_score=10, risk_level="Low",
        )
        p = AttackPath(
            path_id="path-1", nodes=(n,), edges=(),
            attack_score=10, confidence=0.35,
            estimated_impact="Minimal", attack_complexity="Simple",
            likelihood="Low", reasoning="Single.", recommendations=(),
        )
        with pytest.raises(AttributeError):
            p.attack_score = 99  # type: ignore[misc]

    def test_empty_path_id_raises(self) -> None:
        n = AttackNode(
            node_id="n-1", correlation_id="c-1",
            title="T", severity="LOW", category="info",
            attack_surface=None, service=None,
            port=None, protocol=None, asset=None,
            risk_score=10, risk_level="Low",
        )
        with pytest.raises(ValueError, match="path_id"):
            AttackPath(
                path_id="", nodes=(n,), edges=(),
                attack_score=10, confidence=0.35,
                estimated_impact="Minimal", attack_complexity="Simple",
                likelihood="Low", reasoning="", recommendations=(),
            )

    def test_empty_nodes_raises(self) -> None:
        with pytest.raises(ValueError, match="nodes"):
            AttackPath(
                path_id="path-1", nodes=(), edges=(),
                attack_score=10, confidence=0.35,
                estimated_impact="Minimal", attack_complexity="Simple",
                likelihood="Low", reasoning="", recommendations=(),
            )

    def test_attack_score_range(self) -> None:
        n = AttackNode(
            node_id="n-1", correlation_id="c-1",
            title="T", severity="LOW", category="info",
            attack_surface=None, service=None,
            port=None, protocol=None, asset=None,
            risk_score=10, risk_level="Low",
        )
        with pytest.raises(ValueError, match="attack_score"):
            AttackPath(
                path_id="path-1", nodes=(n,), edges=(),
                attack_score=101, confidence=0.35,
                estimated_impact="Minimal", attack_complexity="Simple",
                likelihood="Low", reasoning="", recommendations=(),
            )


class TestAttackGraph:
    def test_creates(self) -> None:
        n = AttackNode(
            node_id="n-1", correlation_id="c-1",
            title="T", severity="HIGH", category="vuln",
            attack_surface="Web", service="HTTP",
            port=80, protocol="TCP", asset="10.0.0.1",
            risk_score=60, risk_level="High",
        )
        p = AttackPath(
            path_id="path-1", nodes=(n,), edges=(),
            attack_score=60, confidence=0.35,
            estimated_impact="High", attack_complexity="Simple",
            likelihood="Medium", reasoning="Single.", recommendations=(),
        )
        g = AttackGraph(
            paths=(p,), total_paths=1,
            highest_score=60, average_score=60.0,
            metadata={"source": "test"},
        )
        assert g.total_paths == 1
        assert g.highest_score == 60

    def test_frozen(self) -> None:
        n = AttackNode(
            node_id="n-1", correlation_id="c-1",
            title="T", severity="LOW", category="info",
            attack_surface=None, service=None,
            port=None, protocol=None, asset=None,
            risk_score=10, risk_level="Low",
        )
        p = AttackPath(
            path_id="path-1", nodes=(n,), edges=(),
            attack_score=10, confidence=0.35,
            estimated_impact="Minimal", attack_complexity="Simple",
            likelihood="Low", reasoning="", recommendations=(),
        )
        g = AttackGraph(
            paths=(p,), total_paths=1,
            highest_score=10, average_score=10.0, metadata={},
        )
        with pytest.raises(AttributeError):
            g.total_paths = 5  # type: ignore[misc]

    def test_empty_paths_raises(self) -> None:
        with pytest.raises(ValueError, match="paths"):
            AttackGraph(
                paths=(), total_paths=0,
                highest_score=0, average_score=0.0, metadata={},
            )

    def test_highest_score_range(self) -> None:
        n = AttackNode(
            node_id="n-1", correlation_id="c-1",
            title="T", severity="LOW", category="info",
            attack_surface=None, service=None,
            port=None, protocol=None, asset=None,
            risk_score=10, risk_level="Low",
        )
        p = AttackPath(
            path_id="path-1", nodes=(n,), edges=(),
            attack_score=10, confidence=0.35,
            estimated_impact="Minimal", attack_complexity="Simple",
            likelihood="Low", reasoning="", recommendations=(),
        )
        with pytest.raises(ValueError, match="highest_score"):
            AttackGraph(
                paths=(p,), total_paths=1,
                highest_score=200, average_score=10.0, metadata={},
            )


class TestAnalyze:
    def test_raises_on_empty(self) -> None:
        with pytest.raises(ValueError, match="assessments"):
            _ENGINE.analyze([])

    def test_singleton_path(self) -> None:
        a = _make_assessment()
        f = _make_finding()
        g = _ENGINE.analyze([a], {"corr-001": f})
        assert g.total_paths == 1
        assert len(g.paths[0].nodes) == 1

    def test_singleton_preserves_score(self) -> None:
        a = _make_assessment(score=75)
        f = _make_finding()
        g = _ENGINE.analyze([a], {"corr-001": f})
        assert g.paths[0].attack_score == 75

    def test_singleton_no_edges(self) -> None:
        a = _make_assessment()
        f = _make_finding()
        g = _ENGINE.analyze([a], {"corr-001": f})
        assert g.paths[0].edges == ()

    def test_returns_attack_graph(self) -> None:
        a = _make_assessment()
        f = _make_finding()
        g = _ENGINE.analyze([a], {"corr-001": f})
        assert isinstance(g, AttackGraph)

    def test_deterministic(self) -> None:
        a = _make_assessment()
        f = _make_finding()
        g1 = _ENGINE.analyze([a], {"corr-001": f})
        g2 = _ENGINE.analyze([a], {"corr-001": f})
        assert g1 == g2

    def test_metadata_counts(self) -> None:
        a = _make_assessment()
        f = _make_finding()
        g = _ENGINE.analyze([a], {"corr-001": f})
        assert g.metadata["total_assessments"] == "1"
        assert g.metadata["total_nodes"] == "1"


class TestEdgeSameAsset:
    def test_same_asset_creates_edge(self) -> None:
        a1 = _make_assessment(correlation_id="corr-001")
        a2 = _make_assessment(correlation_id="corr-002")
        f1 = _make_finding(correlation_id="corr-001", affected_assets=("10.0.0.1",))
        f2 = _make_finding(correlation_id="corr-002", title="Web",
                           affected_assets=("10.0.0.1",), service="HTTP",
                           software=("apache",), port=80,
                           attack_surface="Web Application")
        g = _ENGINE.analyze([a1, a2], {"corr-001": f1, "corr-002": f2})
        assert g.total_paths == 1
        assert len(g.paths[0].nodes) == 2
        assert len(g.paths[0].edges) >= 1

    def test_confidence_is_0_8(self) -> None:
        a1 = _make_assessment(correlation_id="corr-001")
        a2 = _make_assessment(correlation_id="corr-002")
        f1 = _make_finding(correlation_id="corr-001", affected_assets=("10.0.0.1",))
        f2 = _make_finding(correlation_id="corr-002", title="Web",
                           affected_assets=("10.0.0.1",), service="HTTP",
                           software=("apache",), port=80,
                           attack_surface="Web Application")
        g = _ENGINE.analyze([a1, a2], {"corr-001": f1, "corr-002": f2})
        assert g.paths[0].edges[0].confidence == 0.8

    def test_different_assets_no_edge(self) -> None:
        a1 = _make_assessment(correlation_id="corr-001")
        a2 = _make_assessment(correlation_id="corr-002")
        f1 = _make_finding(correlation_id="corr-001", affected_assets=("10.0.0.1",))
        f2 = _make_finding(correlation_id="corr-002", title="Web",
                           affected_assets=("10.0.0.2",), service="HTTP",
                           software=("apache",), port=80, protocol="UDP",
                           attack_surface="Web Application")
        g = _ENGINE.analyze([a1, a2], {"corr-001": f1, "corr-002": f2})
        assert g.total_paths == 2


class TestEdgeSameService:
    def test_same_service_creates_edge(self) -> None:
        a1 = _make_assessment(correlation_id="corr-001")
        a2 = _make_assessment(correlation_id="corr-002")
        f1 = _make_finding(correlation_id="corr-001", affected_assets=("10.0.0.1",),
                           service="HTTP", software=("apache",), port=80)
        f2 = _make_finding(correlation_id="corr-002", title="Nginx",
                           affected_assets=("10.0.0.2",), service="HTTP",
                           software=("nginx",), port=443,
                           attack_surface="Web Application")
        g = _ENGINE.analyze([a1, a2], {"corr-001": f1, "corr-002": f2})
        assert g.total_paths == 1
        assert g.paths[0].edges[0].relationship == "same_service"


class TestEdgeSameSurface:
    def test_same_surface_creates_edge(self) -> None:
        a1 = _make_assessment(correlation_id="corr-001")
        a2 = _make_assessment(correlation_id="corr-002")
        f1 = _make_finding(correlation_id="corr-001", affected_assets=("10.0.0.1",),
                           service="MySQL", software=("mysql",), port=3306,
                           attack_surface="Database")
        f2 = _make_finding(correlation_id="corr-002", title="Redis",
                           affected_assets=("10.0.0.2",), service="Redis",
                           software=("redis",), port=6379,
                           attack_surface="Database")
        g = _ENGINE.analyze([a1, a2], {"corr-001": f1, "corr-002": f2})
        assert g.total_paths == 1
        assert g.paths[0].edges[0].relationship == "same_surface"


class TestEdgeSoftwareDependency:
    def test_software_dep_creates_edge(self) -> None:
        a1 = _make_assessment(correlation_id="corr-001")
        a2 = _make_assessment(correlation_id="corr-002")
        f1 = _make_finding(correlation_id="corr-001", affected_assets=("10.0.0.1",),
                           service="HTTP", software=("apache", "php"),
                           port=80, attack_surface="Web Application")
        f2 = _make_finding(correlation_id="corr-002", title="WP",
                           affected_assets=("10.0.0.2",), service="HTTP",
                           software=("php", "wordpress"), port=443,
                           attack_surface="Web Application")
        g = _ENGINE.analyze([a1, a2], {"corr-001": f1, "corr-002": f2})
        assert g.total_paths == 1

    def test_no_software_overlap(self) -> None:
        a1 = _make_assessment(correlation_id="corr-001")
        a2 = _make_assessment(correlation_id="corr-002")
        f1 = _make_finding(correlation_id="corr-001", affected_assets=("10.0.0.1",),
                           service="SSH", software=("openssh",),
                           port=22, attack_surface="Network Service")
        f2 = _make_finding(correlation_id="corr-002", title="MySQL",
                           affected_assets=("10.0.0.2",), service="MySQL",
                           software=("mysql",), port=3306, protocol="UDP",
                           attack_surface="Database")
        g = _ENGINE.analyze([a1, a2], {"corr-001": f1, "corr-002": f2})
        assert g.total_paths == 2


class TestPathOrdering:
    def test_ordered_by_attack_stage(self) -> None:
        a1 = _make_assessment(correlation_id="corr-dns")
        a2 = _make_assessment(correlation_id="corr-web", score=70,
                              risk_level="High")
        a3 = _make_assessment(correlation_id="corr-db", score=80,
                              risk_level="Critical")
        f1 = _make_finding(correlation_id="corr-dns", title="DNS Issue",
                           affected_assets=("10.0.0.1",), service="DNS",
                           software=("dns",), port=53, attack_surface="DNS")
        f2 = _make_finding(correlation_id="corr-web", title="XSS",
                           affected_assets=("10.0.0.1",), service="HTTP",
                           software=("apache",), port=80,
                           attack_surface="Web Application")
        f3 = _make_finding(correlation_id="corr-db", title="SQLi",
                           affected_assets=("10.0.0.1",), service="MySQL",
                           software=("mysql",), port=3306,
                           attack_surface="Database")
        fm = {"corr-dns": f1, "corr-web": f2, "corr-db": f3}
        g = _ENGINE.analyze([a1, a2, a3], fm)
        assert g.total_paths == 1
        nodes = g.paths[0].nodes
        assert nodes[0].attack_surface == "DNS"
        assert nodes[1].attack_surface == "Web Application"
        assert nodes[2].attack_surface == "Database"


class TestPathScoring:
    def test_weighted_formula(self) -> None:
        a1 = _make_assessment(correlation_id="corr-001", score=80)
        a2 = _make_assessment(correlation_id="corr-002", score=40)
        f1 = _make_finding(correlation_id="corr-001", affected_assets=("10.0.0.1",))
        f2 = _make_finding(correlation_id="corr-002", title="Other",
                           affected_assets=("10.0.0.1",), service="HTTP",
                           software=("apache",), port=80,
                           attack_surface="Web Application")
        g = _ENGINE.analyze([a1, a2], {"corr-001": f1, "corr-002": f2})
        assert g.paths[0].attack_score == 64

    def test_singleton_equals_risk(self) -> None:
        a = _make_assessment(score=55)
        f = _make_finding()
        g = _ENGINE.analyze([a], {"corr-001": f})
        assert g.paths[0].attack_score == 55


class TestGraphRanking:
    def test_sorted_by_score_desc(self) -> None:
        a1 = _make_assessment(correlation_id="corr-001")
        a2 = _make_assessment(correlation_id="corr-002")
        f1 = _make_finding(correlation_id="corr-001", affected_assets=("10.0.0.1",),
                           service="SSH", software=("ssh",), port=22,
                           attack_surface="Network Service")
        f2 = _make_finding(correlation_id="corr-002", title="Web",
                           affected_assets=("10.0.0.2",), service="HTTP",
                           software=("apache",), port=80, protocol="UDP",
                           attack_surface="Web Application")
        g = _ENGINE.analyze([a1, a2], {"corr-001": f1, "corr-002": f2})
        assert g.total_paths == 2

    def test_highest_score(self) -> None:
        a1 = _make_assessment(correlation_id="corr-001", score=90,
                               risk_level="Critical")
        a2 = _make_assessment(correlation_id="corr-002", score=30,
                               risk_level="Low")
        f1 = _make_finding(correlation_id="corr-001", affected_assets=("10.0.0.1",),
                           service="HTTP", software=("apache",), port=80,
                           attack_surface="Web Application")
        f2 = _make_finding(correlation_id="corr-002", title="Other",
                           affected_assets=("10.0.0.2",), service="DNS",
                           software=("dns",), port=53, protocol="UDP",
                           attack_surface="DNS")
        g = _ENGINE.analyze([a1, a2], {"corr-001": f1, "corr-002": f2})
        assert g.highest_score == 90

    def test_average_score(self) -> None:
        a1 = _make_assessment(correlation_id="corr-001", score=80)
        a2 = _make_assessment(correlation_id="corr-002", score=40)
        f1 = _make_finding(correlation_id="corr-001", affected_assets=("10.0.0.1",),
                           service="SSH", software=("ssh",), port=22,
                           attack_surface="Network Service")
        f2 = _make_finding(correlation_id="corr-002", title="Other",
                           affected_assets=("10.0.0.2",), service="HTTP",
                           software=("apache",), port=80, protocol="UDP",
                           attack_surface="Web Application")
        g = _ENGINE.analyze([a1, a2], {"corr-001": f1, "corr-002": f2})
        assert g.average_score == 60.0


class TestPathEstimates:
    def test_impact_severe(self) -> None:
        a1 = _make_assessment(correlation_id="corr-001")
        a2 = _make_assessment(correlation_id="corr-002")
        f1 = _make_finding(correlation_id="corr-001", affected_assets=("10.0.0.1",),
                           business_impact="Low", service="DNS",
                           software=("dns",), port=53, attack_surface="DNS")
        f2 = _make_finding(correlation_id="corr-002", title="DB",
                           affected_assets=("10.0.0.1",),
                           business_impact="Critical", service="MySQL",
                           software=("mysql",), port=3306,
                           attack_surface="Database")
        g = _ENGINE.analyze([a1, a2], {"corr-001": f1, "corr-002": f2})
        assert g.paths[0].estimated_impact == "Severe"

    def test_complexity_hard(self) -> None:
        a = _make_assessment()
        f = _make_finding(remediation_complexity="Hard")
        g = _ENGINE.analyze([a], {"corr-001": f})
        assert g.paths[0].attack_complexity == "Complex"

    def test_complexity_easy(self) -> None:
        a = _make_assessment()
        f = _make_finding(remediation_complexity="Easy")
        g = _ENGINE.analyze([a], {"corr-001": f})
        assert g.paths[0].attack_complexity == "Simple"

    def test_complexity_moderate_3_nodes(self) -> None:
        a1 = _make_assessment(correlation_id="corr-001")
        a2 = _make_assessment(correlation_id="corr-002")
        a3 = _make_assessment(correlation_id="corr-003")
        f1 = _make_finding(correlation_id="corr-001", affected_assets=("10.0.0.1",),
                           service="SSH", software=("ssh",), port=22,
                           attack_surface="Network Service")
        f2 = _make_finding(correlation_id="corr-002", title="Web",
                           affected_assets=("10.0.0.1",), service="HTTP",
                           software=("apache",), port=80,
                           attack_surface="Web Application")
        f3 = _make_finding(correlation_id="corr-003", title="DB",
                           affected_assets=("10.0.0.1",), service="MySQL",
                           software=("mysql",), port=3306,
                           attack_surface="Database")
        fm = {"corr-001": f1, "corr-002": f2, "corr-003": f3}
        g = _ENGINE.analyze([a1, a2, a3], fm)
        assert g.paths[0].attack_complexity == "Moderate"

    def test_likelihood_high(self) -> None:
        a1 = _make_assessment(correlation_id="corr-001")
        a2 = _make_assessment(correlation_id="corr-002")
        f1 = _make_finding(correlation_id="corr-001", affected_assets=("10.0.0.1",),
                           exploit_likelihood="Low", service="SSH",
                           software=("ssh",), port=22, attack_surface="Network")
        f2 = _make_finding(correlation_id="corr-002", title="Web",
                           affected_assets=("10.0.0.1",),
                           exploit_likelihood="High", service="HTTP",
                           software=("apache",), port=80,
                           attack_surface="Web Application")
        g = _ENGINE.analyze([a1, a2], {"corr-001": f1, "corr-002": f2})
        assert g.paths[0].likelihood == "High"

    def test_likelihood_unknown_when_no_data(self) -> None:
        a = _make_assessment()
        f = _make_finding(exploit_likelihood=None)
        g = _ENGINE.analyze([a], {"corr-001": f})
        assert g.paths[0].likelihood == "Unknown"


class TestDeterministic:
    def test_same_input_same_graph(self) -> None:
        a1 = _make_assessment(correlation_id="corr-001")
        a2 = _make_assessment(correlation_id="corr-002")
        f1 = _make_finding(correlation_id="corr-001", affected_assets=("10.0.0.1",))
        f2 = _make_finding(correlation_id="corr-002", title="Web",
                           affected_assets=("10.0.0.1",), service="HTTP",
                           software=("apache",), port=80,
                           attack_surface="Web Application")
        fm = {"corr-001": f1, "corr-002": f2}
        g1 = _ENGINE.analyze([a1, a2], fm)
        g2 = _ENGINE.analyze([a1, a2], fm)
        assert g1 == g2


class TestEdgeCases:
    def test_no_finding_map(self) -> None:
        a1 = _make_assessment(correlation_id="corr-001")
        a2 = _make_assessment(correlation_id="corr-002")
        g = _ENGINE.analyze([a1, a2], {})
        assert g.total_paths == 2

    def test_missing_finding(self) -> None:
        a1 = _make_assessment(correlation_id="corr-001")
        a2 = _make_assessment(correlation_id="corr-002")
        f1 = _make_finding(correlation_id="corr-001", affected_assets=("10.0.0.1",))
        g = _ENGINE.analyze([a1, a2], {"corr-001": f1})
        assert g.total_paths == 2

    def test_recommendations_collected(self) -> None:
        a = _make_assessment()
        f = _make_finding(recommendations=("Fix SSH", "Update OpenSSH"))
        g = _ENGINE.analyze([a], {"corr-001": f})
        assert len(g.paths[0].recommendations) == 2

    def test_reasoning_contains_title(self) -> None:
        a = _make_assessment()
        f = _make_finding(title="Critical SSH Bug")
        g = _ENGINE.analyze([a], {"corr-001": f})
        assert "Critical SSH Bug" in g.paths[0].reasoning

    def test_large_dataset(self) -> None:
        assessments = []
        fm = {}
        for i in range(100):
            cid = f"corr-{i:04d}"
            assessments.append(_make_assessment(correlation_id=cid, score=50))
            fm[cid] = _make_finding(correlation_id=cid, title=f"F{i}",
                                    affected_assets=(f"10.0.0.{i % 10}",),
                                    service="HTTP", software=("apache",),
                                    port=80, attack_surface="Web Application")
        g = _ENGINE.analyze(assessments, fm)
        assert g.total_paths <= 100
        assert g.total_paths >= 1

    def test_node_ordering_by_stage(self) -> None:
        a1 = _make_assessment(correlation_id="corr-001", score=80,
                              risk_level="Critical")
        a2 = _make_assessment(correlation_id="corr-002", score=30,
                              risk_level="Low")
        f1 = _make_finding(correlation_id="corr-001",
                           affected_assets=("10.0.0.1",), service="MySQL",
                           software=("mysql",), port=3306,
                           attack_surface="Database")
        f2 = _make_finding(correlation_id="corr-002", title="Discovery",
                           affected_assets=("10.0.0.1",), service="DNS",
                           software=("dns",), port=53, attack_surface="DNS")
        g = _ENGINE.analyze([a1, a2], {"corr-001": f1, "corr-002": f2})
        assert g.paths[0].nodes[0].attack_surface == "DNS"
        assert g.paths[0].nodes[1].attack_surface == "Database"

    def test_no_finding_map_all_singletons(self) -> None:
        a1 = _make_assessment(correlation_id="corr-001", score=80)
        a2 = _make_assessment(correlation_id="corr-002", score=90)
        g = _ENGINE.analyze([a1, a2])
        assert g.total_paths == 2
        assert g.highest_score == 90
