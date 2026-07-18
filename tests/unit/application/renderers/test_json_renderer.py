"""JSON Report Renderer: comprehensive tests."""

from __future__ import annotations

import dataclasses
import json
from datetime import datetime, timezone
from enum import Enum
from pathlib import Path
from tempfile import NamedTemporaryFile

import pytest

from kingsec.application.attack_path import (
    AttackEdge,
    AttackGraph,
    AttackNode,
    AttackPath,
)
from kingsec.application.report import (
    Appendix,
    AssetEntry,
    AssetSummary,
    AttackPathSection,
    ExecutiveSummary,
    FindingEntry,
    FindingSection,
    RecommendationEntry,
    RecommendationSection,
    Report,
    RiskSummary,
    TechnicalSummary,
)
from kingsec.application.renderers.json_renderer import JsonReportRenderer

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

_RENDERER = JsonReportRenderer()
_NOW = datetime(2026, 7, 17, tzinfo=timezone.utc)


def _es(
    total_findings: int = 10,
    critical: int = 2,
    high: int = 3,
    medium: int = 3,
    low: int = 1,
    informational: int = 1,
    top_score: int = 95,
    avg_score: float = 55.5,
    assets: int = 3,
    text: str = "Security scan found 10 findings across 3 assets.",
) -> ExecutiveSummary:
    return ExecutiveSummary(
        total_findings=total_findings,
        total_correlated=total_findings,
        total_enriched=total_findings,
        total_risk_assessments=total_findings,
        critical_count=critical,
        high_count=high,
        medium_count=medium,
        low_count=low,
        informational_count=informational,
        top_risk_score=top_score,
        average_risk_score=avg_score,
        total_assets=assets,
        summary_text=text,
    )


def _ts() -> TechnicalSummary:
    return TechnicalSummary(
        total_findings=10,
        total_correlations=10,
        total_enriched=10,
        total_risk_assessments=10,
        severity_breakdown={"CRITICAL": 2, "HIGH": 3},
        category_breakdown={"vulnerability": 8, "misconfiguration": 2},
        scanner_coverage={"nuclei": 5, "nmap": 3, "nikto": 2},
    )


def _rs(
    dist: dict[str, int] | None = None,
    avg: float = 55.5,
    high: int = 95,
    low: int = 10,
) -> RiskSummary:
    return RiskSummary(
        score_distribution=dist or {
            "Critical": 2, "High": 3, "Medium": 3, "Low": 1, "Informational": 1,
        },
        average_score=avg,
        highest_score=high,
        lowest_score=low,
        top_risk_factors=("Remote Code Execution", "SQL Injection"),
    )


def _finding_entry(
    cid: str = "corr-001",
    title: str = "SSH Vulnerability",
    severity: str = "HIGH",
    score: int = 75,
    assets: tuple[str, ...] = ("10.0.0.1",),
) -> FindingEntry:
    return FindingEntry(
        correlation_id=cid,
        title=title,
        severity=severity,
        category="vulnerability",
        confidence=0.8,
        scanner_sources=("nuclei",),
        affected_assets=assets,
        service="SSH",
        port=22,
        protocol="TCP",
        attack_surface="Network Service",
        risk_score=score,
        risk_level="High",
        priority="High",
    )


def _asset_entry(
    asset: str = "10.0.0.1",
    count: int = 5,
    high: int = 90,
    avg: float = 55.5,
) -> AssetEntry:
    return AssetEntry(
        asset=asset,
        finding_count=count,
        highest_risk_score=high,
        average_risk_score=avg,
    )


def _rec_entry(
    title: str = "SSH Vulnerability",
    severity: str = "HIGH",
    score: int = 75,
    cid: str = "corr-001",
    recs: tuple[str, ...] = ("Update OpenSSH", "Disable root login"),
) -> RecommendationEntry:
    return RecommendationEntry(
        finding_title=title,
        severity=severity,
        risk_score=score,
        correlation_id=cid,
        recommendations=recs,
    )


def _attack_node(
    cid: str = "corr-001",
    title: str = "SSH Vuln",
    score: int = 75,
) -> AttackNode:
    return AttackNode(
        node_id=f"node-{cid}",
        correlation_id=cid,
        title=title,
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


def _graph(
    node_scores: list[int] | None = None,
) -> AttackGraph:
    if node_scores is None:
        node_scores = [75]
    nodes = [
        _attack_node(f"corr-{i:04d}", f"Finding {i}", s)
        for i, s in enumerate(node_scores)
    ]
    edges: list[AttackEdge] = []
    for i in range(len(nodes) - 1):
        edges.append(AttackEdge(
            source_id=nodes[i].node_id,
            target_id=nodes[i + 1].node_id,
            relationship="same_asset",
            confidence=0.8,
        ))
    scores = [n.risk_score for n in nodes]
    max_s = max(scores) if scores else 0
    avg_s = sum(scores) / len(scores) if scores else 0.0
    as_val = min(int(max_s * 0.6 + avg_s * 0.4), 100)
    p = AttackPath(
        path_id="path-001",
        nodes=tuple(nodes),
        edges=tuple(edges),
        attack_score=as_val,
        confidence=0.8 if edges else 0.35,
        estimated_impact="High",
        attack_complexity="Moderate",
        likelihood="Medium",
        reasoning="Attack chain detected.",
        recommendations=("Review access controls",),
    )
    return AttackGraph(
        paths=(p,),
        total_paths=1,
        highest_score=as_val,
        average_score=float(as_val),
        metadata={"total_assessments": str(len(nodes))},
    )


def _appendix() -> Appendix:
    return Appendix(
        scanner_versions={"nuclei": "3.2.1", "nmap": "7.95"},
        total_plugins=2,
        generated_at=_NOW,
        generated_by="KingSec Report Builder",
    )


def _minimal_report() -> Report:
    es = _es(
        total_findings=1, critical=0, high=1, medium=0, low=0, informational=0,
        top_score=75, avg_score=75.0, assets=1,
        text="Security scan found 1 finding across 1 asset.",
    )
    ts = TechnicalSummary(
        total_findings=1, total_correlations=1, total_enriched=1,
        total_risk_assessments=1,
        severity_breakdown={"HIGH": 1},
        category_breakdown={"vulnerability": 1},
        scanner_coverage={"nuclei": 1},
    )
    rs = _rs(dist={"High": 1}, avg=75.0, high=75, low=75)
    ae = _asset_entry(asset="10.0.0.1", count=1, high=75, avg=75.0)
    fe = _finding_entry()
    fs = FindingSection(entries=(fe,), total_count=1, severity_breakdown={"HIGH": 1})
    aps = AttackPathSection(
        total_paths=1, highest_score=75, average_score=75.0,
        graph=_graph(),
    )
    rec_e = _rec_entry()
    recs = RecommendationSection(entries=(rec_e,), total_recommendations=2)
    app = _appendix()
    return Report(
        report_id="rpt-001",
        title="KingSec Security Report",
        created_at=_NOW,
        executive_summary=es,
        technical_summary=ts,
        risk_summary=rs,
        asset_summary=AssetSummary(entries=(ae,), total_assets=1),
        finding_section=fs,
        attack_path_section=aps,
        recommendation_section=recs,
        appendix=app,
    )


def _empty_report() -> Report:
    es = _es(
        total_findings=0, critical=0, high=0, medium=0, low=0, informational=0,
        top_score=0, avg_score=0.0, assets=0,
        text="No findings were discovered during the scan.",
    )
    ts = TechnicalSummary(
        total_findings=0, total_correlations=0, total_enriched=0,
        total_risk_assessments=0,
        severity_breakdown={}, category_breakdown={}, scanner_coverage={},
    )
    rs = _rs(dist={}, avg=0.0, high=0, low=0)
    fs = FindingSection(entries=(), total_count=0, severity_breakdown={})
    n1 = _attack_node("corr-dummy", "Dummy", 0)
    p = AttackPath(
        path_id="path-empty", nodes=(n1,), edges=(),
        attack_score=0, confidence=0.0,
        estimated_impact="None", attack_complexity="Simple",
        likelihood="Low", reasoning="Empty.", recommendations=(),
    )
    ag = AttackGraph(paths=(p,), total_paths=0, highest_score=0,
                     average_score=0.0, metadata={})
    aps = AttackPathSection(
        total_paths=0, highest_score=0, average_score=0.0, graph=ag,
    )
    recs = RecommendationSection(entries=(), total_recommendations=0)
    app = Appendix(
        scanner_versions={}, total_plugins=0,
        generated_at=_NOW, generated_by="KingSec Report Builder",
    )
    return Report(
        report_id="rpt-empty",
        title="KingSec Security Report",
        created_at=_NOW,
        executive_summary=es,
        technical_summary=ts,
        risk_summary=rs,
        asset_summary=AssetSummary(entries=(), total_assets=0),
        finding_section=fs,
        attack_path_section=aps,
        recommendation_section=recs,
        appendix=app,
    )


def _multi_report() -> Report:
    es = _es(
        total_findings=5, critical=1, high=2, medium=1, low=1, informational=0,
        top_score=95, avg_score=60.0, assets=3,
        text="Security scan found 5 findings across 3 assets.",
    )
    ts = TechnicalSummary(
        total_findings=5, total_correlations=5, total_enriched=5,
        total_risk_assessments=5,
        severity_breakdown={"CRITICAL": 1, "HIGH": 2, "MEDIUM": 1, "LOW": 1},
        category_breakdown={"vulnerability": 3, "misconfiguration": 1, "info": 1},
        scanner_coverage={"nuclei": 3, "nmap": 2},
    )
    rs = RiskSummary(
        score_distribution={"Critical": 1, "High": 2, "Medium": 1, "Low": 1},
        average_score=60.0, highest_score=95, lowest_score=15,
        top_risk_factors=("RCE", "SQLi", "XSS"),
    )
    fe1 = _finding_entry("corr-001", "RCE in Apache", "CRITICAL", 95)
    fe2 = _finding_entry("corr-002", "XSS in Web App", "HIGH", 75, assets=("10.0.0.2",))
    fe3 = _finding_entry("corr-003", "Weak Ciphers", "MEDIUM", 50)
    fe4 = _finding_entry(
        "corr-004", "Info Leak", "LOW", 15,
        assets=("10.0.0.1", "10.0.0.3"),
    )
    fs = FindingSection(
        entries=(fe1, fe2, fe3, fe4),
        total_count=4,
        severity_breakdown={"CRITICAL": 1, "HIGH": 1, "MEDIUM": 1, "LOW": 1},
    )
    ag = _graph([95, 75, 50])
    aps = AttackPathSection(
        total_paths=1, highest_score=75, average_score=75.0, graph=ag,
    )
    ae1 = _asset_entry("10.0.0.1", 2, 95, 85.0)
    ae2 = _asset_entry("10.0.0.2", 2, 75, 62.5)
    ae3 = _asset_entry("10.0.0.3", 1, 50, 50.0)
    asset_sum = AssetSummary(entries=(ae1, ae2, ae3), total_assets=3)
    re1 = _rec_entry(
        "RCE in Apache", "CRITICAL", 95, "corr-001",
        ("Patch Apache", "Update firewall rules"),
    )
    re2 = _rec_entry(
        "XSS in Web App", "HIGH", 75, "corr-002",
        ("Sanitize inputs",),
    )
    recs = RecommendationSection(entries=(re1, re2), total_recommendations=3)
    app = Appendix(
        scanner_versions={"nuclei": "3.2.1", "nmap": "7.95", "nikto": "2.5.0"},
        total_plugins=3,
        generated_at=_NOW,
        generated_by="KingSec Report Builder",
    )
    return Report(
        report_id="rpt-002",
        title="KingSec Security Report",
        created_at=_NOW,
        executive_summary=es,
        technical_summary=ts,
        risk_summary=rs,
        asset_summary=asset_sum,
        finding_section=fs,
        attack_path_section=aps,
        recommendation_section=recs,
        appendix=app,
    )


def _unicode_report() -> Report:
    fe = FindingEntry(
        correlation_id="corr-unicode",
        title="Caf\u00e9 vuln r\u00e9sum\u00e9",
        severity="HIGH",
        category="vulnerability",
        confidence=0.8,
        scanner_sources=("nuclei\u2728",),
        affected_assets=("M\u00fcnchen-01", "Z\u00fcrich-02"),
        service="HTTP",
        port=80,
        protocol="TCP",
        attack_surface="Web",
        risk_score=75,
        risk_level="High",
        priority="High",
    )
    fs = FindingSection(
        entries=(fe,), total_count=1, severity_breakdown={"HIGH": 1},
    )
    app = Appendix(
        scanner_versions={"nuclei\u2728": "3.0"},
        total_plugins=1,
        generated_at=_NOW,
        generated_by="KingSec",
    )
    es = _es(
        total_findings=1, critical=0, high=1, medium=0, low=0, informational=0,
        top_score=75, avg_score=75.0, assets=2,
        text="Caf\u00e9 r\u00e9sum\u00e9 \u00e0 v\u00e9rifier.",
    )
    ts = TechnicalSummary(
        total_findings=1, total_correlations=1, total_enriched=1,
        total_risk_assessments=1,
        severity_breakdown={"HIGH": 1},
        category_breakdown={"vulnerability": 1},
        scanner_coverage={"nuclei\u2728": 1},
    )
    rs = _rs(dist={"High": 1}, avg=75.0, high=75, low=75)
    aps = AttackPathSection(
        total_paths=0, highest_score=0, average_score=0.0,
        graph=_graph([0]),
    )
    recs = RecommendationSection(entries=(), total_recommendations=0)
    return Report(
        report_id="rpt-unicode",
        title="KingSec Security Report",
        created_at=_NOW,
        executive_summary=es,
        technical_summary=ts,
        risk_summary=rs,
        asset_summary=AssetSummary(
            entries=(_asset_entry("M\u00fcnchen-01", 1, 75, 75.0),),
            total_assets=1,
        ),
        finding_section=fs,
        attack_path_section=aps,
        recommendation_section=recs,
        appendix=app,
    )


def _make_large_report() -> Report:
    """Build a report with 50 findings for large-render testing."""
    findings: list[FindingEntry] = []
    recs: list[RecommendationEntry] = []
    nodes: list[AttackNode] = []
    score_dist: dict[str, int] = {}
    sev_breakdown: dict[str, int] = {}
    category_breakdown: dict[str, int] = {}

    for i in range(50):
        sev = ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"][i % 5]
        score = 100 - i * 2
        cid = f"finding-{i:04d}"
        fe = FindingEntry(
            correlation_id=cid,
            title=f"Finding {i}",
            severity=sev,
            category="vulnerability",
            confidence=0.85,
            scanner_sources=("nuclei",),
            affected_assets=(f"asset-{i % 10:04d}",),
            service="HTTP" if i % 2 == 0 else "SSH",
            port=80 if i % 2 == 0 else 22,
            protocol="TCP",
            attack_surface="Web" if i % 2 == 0 else "Network",
            risk_score=score,
            risk_level=sev.title(),
            priority=sev.title(),
        )
        findings.append(fe)

        recs.append(RecommendationEntry(
            finding_title=fe.title,
            severity=sev,
            risk_score=score,
            correlation_id=cid,
            recommendations=(f"Fix issue {i} - step 1", f"Fix issue {i} - step 2"),
        ))

        nn = AttackNode(
            node_id=f"node-{cid}",
            correlation_id=cid,
            title=fe.title,
            severity=sev,
            category="vulnerability",
            attack_surface="Web",
            service="HTTP",
            port=80,
            protocol="TCP",
            asset=f"asset-{i % 10:04d}",
            risk_score=score,
            risk_level=sev.title(),
        )
        nodes.append(nn)

        score_dist[sev.title()] = score_dist.get(sev.title(), 0) + 1
        sev_breakdown[sev] = sev_breakdown.get(sev, 0) + 1
        cat = "vulnerability" if i % 5 != 4 else "info"
        category_breakdown[cat] = category_breakdown.get(cat, 0) + 1

    edges: list[AttackEdge] = []
    for i in range(min(10, len(nodes) - 1)):
        edges.append(AttackEdge(
            source_id=nodes[i].node_id,
            target_id=nodes[i + 1].node_id,
            relationship="same_asset",
            confidence=0.8,
        ))

    scores = [n.risk_score for n in nodes]
    as_val = min(int(max(scores) * 0.6 + (sum(scores) / len(scores)) * 0.4), 100)

    path_obj = AttackPath(
        path_id="path-large",
        nodes=tuple(nodes),
        edges=tuple(edges),
        attack_score=as_val,
        confidence=0.85,
        estimated_impact="High",
        attack_complexity="Moderate",
        likelihood="Medium",
        reasoning="Large attack chain detected across multiple assets.",
        recommendations=("Review access controls", "Patch vulnerabilities"),
    )
    ag = AttackGraph(
        paths=(path_obj,),
        total_paths=1,
        highest_score=as_val,
        average_score=float(as_val),
        metadata={"total_assessments": str(len(nodes))},
    )

    es = ExecutiveSummary(
        total_findings=50,
        total_correlated=50,
        total_enriched=50,
        total_risk_assessments=50,
        critical_count=10,
        high_count=10,
        medium_count=10,
        low_count=10,
        informational_count=10,
        top_risk_score=100,
        average_risk_score=50.0,
        total_assets=10,
        summary_text="Security scan found 50 findings across 10 assets.",
    )

    ts = TechnicalSummary(
        total_findings=50,
        total_correlations=50,
        total_enriched=50,
        total_risk_assessments=50,
        severity_breakdown=sev_breakdown,
        category_breakdown=category_breakdown,
        scanner_coverage={"nuclei": 50},
    )

    rs = RiskSummary(
        score_distribution=score_dist,
        average_score=50.0,
        highest_score=100,
        lowest_score=2,
        top_risk_factors=("Remote Code Execution", "SQL Injection", "XSS"),
    )

    assets_list: list[AssetEntry] = []
    for i in range(10):
        assets_list.append(AssetEntry(
            asset=f"asset-{i:04d}",
            finding_count=5,
            highest_risk_score=100 - i * 10,
            average_risk_score=50.0,
        ))

    aps = AttackPathSection(
        total_paths=1,
        highest_score=as_val,
        average_score=float(as_val),
        graph=ag,
    )

    return Report(
        report_id="rpt-large",
        title="KingSec Security Report",
        created_at=_NOW,
        executive_summary=es,
        technical_summary=ts,
        risk_summary=rs,
        asset_summary=AssetSummary(entries=tuple(assets_list), total_assets=10),
        finding_section=FindingSection(
            entries=tuple(findings),
            total_count=50,
            severity_breakdown=sev_breakdown,
        ),
        attack_path_section=aps,
        recommendation_section=RecommendationSection(
            entries=tuple(recs),
            total_recommendations=100,
        ),
        appendix=Appendix(
            scanner_versions={"nuclei": "3.2.1", "nmap": "7.95"},
            total_plugins=2,
            generated_at=_NOW,
            generated_by="KingSec Report Builder",
        ),
    )


# ===========================================================================
# Simple report
# ===========================================================================


class TestSimpleReport:
    def test_returns_string(self) -> None:
        result = _RENDERER.render(_minimal_report())
        assert isinstance(result, str)

    def test_valid_json(self) -> None:
        result = _RENDERER.render(_minimal_report())
        doc = json.loads(result)
        assert isinstance(doc, dict)

    def test_top_level_fields(self) -> None:
        doc = json.loads(_RENDERER.render(_minimal_report()))
        assert doc["report_id"] == "rpt-001"
        assert doc["title"] == "KingSec Security Report"

    def test_has_executive_summary(self) -> None:
        doc = json.loads(_RENDERER.render(_minimal_report()))
        assert "executive_summary" in doc
        es = doc["executive_summary"]
        assert es["total_findings"] == 1
        assert es["summary_text"] == "Security scan found 1 finding across 1 asset."

    def test_has_technical_summary(self) -> None:
        doc = json.loads(_RENDERER.render(_minimal_report()))
        assert "technical_summary" in doc

    def test_has_risk_summary(self) -> None:
        doc = json.loads(_RENDERER.render(_minimal_report()))
        assert "risk_summary" in doc

    def test_has_asset_summary(self) -> None:
        doc = json.loads(_RENDERER.render(_minimal_report()))
        assert "asset_summary" in doc

    def test_has_finding_section(self) -> None:
        doc = json.loads(_RENDERER.render(_minimal_report()))
        assert "finding_section" in doc

    def test_has_attack_path_section(self) -> None:
        doc = json.loads(_RENDERER.render(_minimal_report()))
        assert "attack_path_section" in doc

    def test_has_recommendation_section(self) -> None:
        doc = json.loads(_RENDERER.render(_minimal_report()))
        assert "recommendation_section" in doc

    def test_has_appendix(self) -> None:
        doc = json.loads(_RENDERER.render(_minimal_report()))
        assert "appendix" in doc

    def test_finding_entry_fields(self) -> None:
        doc = json.loads(_RENDERER.render(_minimal_report()))
        entries = doc["finding_section"]["entries"]
        assert len(entries) == 1
        fe = entries[0]
        assert fe["correlation_id"] == "corr-001"
        assert fe["title"] == "SSH Vulnerability"
        assert fe["severity"] == "HIGH"
        assert fe["risk_score"] == 75
        assert fe["confidence"] == 0.8
        assert fe["scanner_sources"] == ["nuclei"]
        assert fe["affected_assets"] == ["10.0.0.1"]

    def test_risk_summary_top_risk_factors(self) -> None:
        doc = json.loads(_RENDERER.render(_minimal_report()))
        factors = doc["risk_summary"]["top_risk_factors"]
        assert isinstance(factors, list)
        assert "Remote Code Execution" in factors
        assert "SQL Injection" in factors


# ===========================================================================
# Empty report
# ===========================================================================


class TestEmptyReport:
    def test_empty_report_has_no_findings(self) -> None:
        doc = json.loads(_RENDERER.render(_empty_report()))
        assert len(doc["finding_section"]["entries"]) == 0
        assert doc["finding_section"]["total_count"] == 0

    def test_empty_report_has_no_assets(self) -> None:
        doc = json.loads(_RENDERER.render(_empty_report()))
        assert len(doc["asset_summary"]["entries"]) == 0
        assert doc["asset_summary"]["total_assets"] == 0

    def test_empty_report_has_no_recommendations(self) -> None:
        doc = json.loads(_RENDERER.render(_empty_report()))
        assert doc["recommendation_section"]["total_recommendations"] == 0

    def test_empty_report_still_has_sections(self) -> None:
        doc = json.loads(_RENDERER.render(_empty_report()))
        assert "executive_summary" in doc
        assert "attack_path_section" in doc
        assert "appendix" in doc

    def test_empty_report_zero_counts(self) -> None:
        doc = json.loads(_RENDERER.render(_empty_report()))
        es = doc["executive_summary"]
        assert es["total_findings"] == 0
        assert es["critical_count"] == 0
        assert es["high_count"] == 0


# ===========================================================================
# Large report
# ===========================================================================


class TestLargeReport:
    def test_large_report_50_findings(self) -> None:
        doc = json.loads(_RENDERER.render(_make_large_report()))
        assert len(doc["finding_section"]["entries"]) == 50

    def test_large_report_finding_ids(self) -> None:
        doc = json.loads(_RENDERER.render(_make_large_report()))
        entry_ids = [e["correlation_id"] for e in doc["finding_section"]["entries"]]
        assert "finding-0000" in entry_ids
        assert "finding-0049" in entry_ids

    def test_large_report_all_severities(self) -> None:
        doc = json.loads(_RENDERER.render(_make_large_report()))
        severities = {e["severity"] for e in doc["finding_section"]["entries"]}
        assert severities == {"CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"}

    def test_large_report_10_assets(self) -> None:
        doc = json.loads(_RENDERER.render(_make_large_report()))
        assert doc["asset_summary"]["total_assets"] == 10
        assert len(doc["asset_summary"]["entries"]) == 10

    def test_large_report_100_recommendations(self) -> None:
        doc = json.loads(_RENDERER.render(_make_large_report()))
        assert doc["recommendation_section"]["total_recommendations"] == 100

    def test_large_report_risk_summary(self) -> None:
        doc = json.loads(_RENDERER.render(_make_large_report()))
        rs = doc["risk_summary"]
        assert rs["highest_score"] == 100
        assert rs["lowest_score"] == 2
        assert len(rs["top_risk_factors"]) == 3


# ===========================================================================
# Multiple findings
# ===========================================================================


class TestMultiFindings:
    def test_all_findings_present(self) -> None:
        doc = json.loads(_RENDERER.render(_multi_report()))
        titles = [e["title"] for e in doc["finding_section"]["entries"]]
        assert "RCE in Apache" in titles
        assert "XSS in Web App" in titles
        assert "Weak Ciphers" in titles
        assert "Info Leak" in titles

    def test_severity_breakdown(self) -> None:
        doc = json.loads(_RENDERER.render(_multi_report()))
        sb = doc["finding_section"]["severity_breakdown"]
        assert sb["CRITICAL"] == 1
        assert sb["HIGH"] == 1
        assert sb["MEDIUM"] == 1
        assert sb["LOW"] == 1

    def test_all_assets_in_asset_summary(self) -> None:
        doc = json.loads(_RENDERER.render(_multi_report()))
        asset_names = [e["asset"] for e in doc["asset_summary"]["entries"]]
        assert "10.0.0.1" in asset_names
        assert "10.0.0.2" in asset_names
        assert "10.0.0.3" in asset_names

    def test_recommendations_match_findings(self) -> None:
        doc = json.loads(_RENDERER.render(_multi_report()))
        rec_titles = [e["finding_title"] for e in doc["recommendation_section"]["entries"]]
        assert "RCE in Apache" in rec_titles
        assert "XSS in Web App" in rec_titles


# ===========================================================================
# Unicode
# ===========================================================================


class TestUnicode:
    def test_unicode_title(self) -> None:
        doc = json.loads(_RENDERER.render(_unicode_report()))
        title = doc["finding_section"]["entries"][0]["title"]
        assert title == "Caf\u00e9 vuln r\u00e9sum\u00e9"

    def test_unicode_asset(self) -> None:
        doc = json.loads(_RENDERER.render(_unicode_report()))
        assets = doc["finding_section"]["entries"][0]["affected_assets"]
        assert "M\u00fcnchen-01" in assets
        assert "Z\u00fcrich-02" in assets

    def test_unicode_scanner(self) -> None:
        doc = json.loads(_RENDERER.render(_unicode_report()))
        scanners = doc["finding_section"]["entries"][0]["scanner_sources"]
        assert "nuclei\u2728" in scanners

    def test_json_is_utf8(self) -> None:
        result = _RENDERER.render(_unicode_report())
        result_bytes = result.encode("utf-8")
        doc = json.loads(result_bytes)
        assert doc["report_id"] == "rpt-unicode"

    def test_unicode_summary_text(self) -> None:
        doc = json.loads(_RENDERER.render(_unicode_report()))
        text = doc["executive_summary"]["summary_text"]
        assert "Caf\u00e9" in text


# ===========================================================================
# Datetime serialization
# ===========================================================================


class TestDatetimeSerialization:
    def test_created_at_iso_format(self) -> None:
        doc = json.loads(_RENDERER.render(_minimal_report()))
        assert doc["created_at"] == "2026-07-17T00:00:00+00:00"

    def test_appendix_generated_at_iso(self) -> None:
        doc = json.loads(_RENDERER.render(_minimal_report()))
        assert doc["appendix"]["generated_at"] == "2026-07-17T00:00:00+00:00"


# ===========================================================================
# Tuple serialization
# ===========================================================================


class TestTupleSerialization:
    def test_top_risk_factors_as_list(self) -> None:
        doc = json.loads(_RENDERER.render(_minimal_report()))
        factors = doc["risk_summary"]["top_risk_factors"]
        assert isinstance(factors, list)
        assert factors == ["Remote Code Execution", "SQL Injection"]

    def test_scanner_sources_as_list(self) -> None:
        doc = json.loads(_RENDERER.render(_minimal_report()))
        sources = doc["finding_section"]["entries"][0]["scanner_sources"]
        assert isinstance(sources, list)
        assert sources == ["nuclei"]

    def test_affected_assets_as_list(self) -> None:
        doc = json.loads(_RENDERER.render(_minimal_report()))
        assets = doc["finding_section"]["entries"][0]["affected_assets"]
        assert isinstance(assets, list)
        assert assets == ["10.0.0.1"]

    def test_recommendations_as_list(self) -> None:
        doc = json.loads(_RENDERER.render(_minimal_report()))
        recs = doc["recommendation_section"]["entries"][0]["recommendations"]
        assert isinstance(recs, list)
        assert recs == ["Update OpenSSH", "Disable root login"]

    def test_path_nodes_as_list(self) -> None:
        doc = json.loads(_RENDERER.render(_minimal_report()))
        paths = doc["attack_path_section"]["graph"]["paths"]
        assert isinstance(paths, list)
        assert len(paths) >= 1
        nodes = paths[0]["nodes"]
        assert isinstance(nodes, list)
        assert len(nodes) >= 1

    def test_path_recommendations_as_list(self) -> None:
        doc = json.loads(_RENDERER.render(_minimal_report()))
        paths = doc["attack_path_section"]["graph"]["paths"]
        recs = paths[0]["recommendations"]
        assert isinstance(recs, list)


# ===========================================================================
# Nested dataclasses
# ===========================================================================


class TestNestedDataclasses:
    def test_report_contains_all_dataclasses(self) -> None:
        doc = json.loads(_RENDERER.render(_minimal_report()))
        assert all(k in doc for k in [
            "report_id", "title", "created_at",
            "executive_summary", "technical_summary", "risk_summary",
            "asset_summary", "finding_section", "attack_path_section",
            "recommendation_section", "appendix",
        ])

    def test_finding_entry_has_all_fields(self) -> None:
        doc = json.loads(_RENDERER.render(_minimal_report()))
        fe = doc["finding_section"]["entries"][0]
        assert all(k in fe for k in [
            "correlation_id", "title", "severity", "category",
            "confidence", "scanner_sources", "affected_assets",
            "service", "port", "protocol", "attack_surface",
            "risk_score", "risk_level", "priority",
        ])

    def test_attack_graph_nested_objects(self) -> None:
        doc = json.loads(_RENDERER.render(_minimal_report()))
        graph = doc["attack_path_section"]["graph"]
        assert "paths" in graph
        assert "total_paths" in graph
        assert "highest_score" in graph
        assert "average_score" in graph
        path = graph["paths"][0]
        assert "path_id" in path
        assert "nodes" in path
        assert "edges" in path
        node = path["nodes"][0]
        assert "node_id" in node
        assert "title" in node
        if path["edges"]:
            edge = path["edges"][0]
            assert "source_id" in edge
            assert "target_id" in edge

    def test_nullable_fields_handled(self) -> None:
        fe = FindingEntry(
            correlation_id="c-null",
            title="Null Test",
            severity="LOW",
            category="info",
            confidence=0.3,
            scanner_sources=(),
            affected_assets=(),
            service=None,
            port=None,
            protocol=None,
            attack_surface=None,
            risk_score=0,
            risk_level="Low",
            priority="None",
        )
        fs = FindingSection(entries=(fe,), total_count=1, severity_breakdown={"LOW": 1})
        es = _es(
            total_findings=1, critical=0, high=0, medium=0, low=1, informational=0,
            top_score=0, avg_score=0.0, assets=0,
            text="Nullable fields test.",
        )
        ts = TechnicalSummary(
            total_findings=1, total_correlations=1, total_enriched=1,
            total_risk_assessments=1,
            severity_breakdown={"LOW": 1}, category_breakdown={"info": 1},
            scanner_coverage={},
        )
        rs = _rs(dist={"Low": 1}, avg=0.0, high=0, low=0)
        n1 = _attack_node("c-null", "Null Test", 0)
        p = AttackPath(
            path_id="path-null", nodes=(n1,), edges=(),
            attack_score=0, confidence=0.0,
            estimated_impact="None", attack_complexity="Simple",
            likelihood="Low", reasoning=".", recommendations=(),
        )
        ag = AttackGraph(paths=(p,), total_paths=1,
                         highest_score=0, average_score=0.0, metadata={})
        aps = AttackPathSection(total_paths=0, highest_score=0, average_score=0.0, graph=ag)
        recs = RecommendationSection(entries=(), total_recommendations=0)
        app = Appendix(
            scanner_versions={}, total_plugins=0,
            generated_at=_NOW, generated_by="KingSec",
        )
        r = Report(
            report_id="rpt-null", title="Null Fields", created_at=_NOW,
            executive_summary=es, technical_summary=ts, risk_summary=rs,
            asset_summary=AssetSummary(entries=(), total_assets=0),
            finding_section=fs, attack_path_section=aps,
            recommendation_section=recs, appendix=app,
        )
        doc = json.loads(_RENDERER.render(r))
        fe_serialized = doc["finding_section"]["entries"][0]
        assert fe_serialized["service"] is None
        assert fe_serialized["port"] is None
        assert fe_serialized["protocol"] is None
        assert fe_serialized["attack_surface"] is None


# ===========================================================================
# Enum serialization
# ===========================================================================


class TestEnumSerialization:
    def test_enum_value_serialized(self) -> None:
        class _TestEnum(Enum):
            FOO = "bar"
            BAZ = 42

        @dataclasses.dataclass
        class _WithEnum:
            name: str
            kind: _TestEnum

        from kingsec.application.renderers.json_renderer import _serialize_value
        result = _serialize_value(_WithEnum(name="test", kind=_TestEnum.FOO))
        assert result["kind"] == "bar"

    def test_int_enum_serialized(self) -> None:
        from enum import IntEnum

        class _TestIntEnum(IntEnum):
            LOW = 0
            HIGH = 1

        from kingsec.application.renderers.json_renderer import _serialize_value
        result = _serialize_value(_TestIntEnum.HIGH)
        assert result == 1

    def test_enum_in_nested_dataclass(self) -> None:
        from enum import Enum

        class _Status(Enum):
            ACTIVE = "active"
            INACTIVE = "inactive"

        @dataclasses.dataclass
        class _Inner:
            status: _Status

        @dataclasses.dataclass
        class _Outer:
            inner: _Inner
            label: str

        from kingsec.application.renderers.json_renderer import _serialize_value
        obj = _Outer(inner=_Inner(status=_Status.ACTIVE), label="test")
        result = _serialize_value(obj)
        assert result["inner"]["status"] == "active"

    def test_enum_as_null(self) -> None:
        from enum import Enum

        class _TestEnum(Enum):
            A = 1

        @dataclasses.dataclass
        class _WithOptional:
            field: _TestEnum | None

        from kingsec.application.renderers.json_renderer import _serialize_value
        result = _serialize_value(_WithOptional(field=None))
        assert result["field"] is None


# ===========================================================================
# Deterministic rendering
# ===========================================================================


class TestDeterministic:
    def test_same_input_same_output(self) -> None:
        report = _minimal_report()
        s1 = _RENDERER.render(report)
        s2 = _RENDERER.render(report)
        assert s1 == s2

    def test_sort_keys(self) -> None:
        doc = json.loads(_RENDERER.render(_minimal_report()))
        keys = list(doc.keys())
        assert keys == sorted(keys)

    def test_stable_ordering_multi(self) -> None:
        r1 = _multi_report()
        r2 = _multi_report()
        assert _RENDERER.render(r1) == _RENDERER.render(r2)

    def test_large_report_deterministic(self) -> None:
        r1 = _make_large_report()
        r2 = _make_large_report()
        assert _RENDERER.render(r1) == _RENDERER.render(r2)

    def test_finding_entries_stable_order(self) -> None:
        doc = json.loads(_RENDERER.render(_multi_report()))
        ids = [e["correlation_id"] for e in doc["finding_section"]["entries"]]
        assert ids == [
            "corr-001", "corr-002", "corr-003", "corr-004",
        ]


# ===========================================================================
# File writing
# ===========================================================================


class TestFileWriting:
    def test_write_creates_file(self) -> None:
        report = _minimal_report()
        with NamedTemporaryFile(mode="w", suffix=".json", delete=False, encoding="utf-8") as f:
            path = Path(f.name)
        try:
            _RENDERER.write(report, path)
            assert path.exists()
            content = path.read_text(encoding="utf-8")
            doc = json.loads(content)
            assert doc["report_id"] == "rpt-001"
        finally:
            path.unlink(missing_ok=True)

    def test_write_utf8_encoding(self) -> None:
        with NamedTemporaryFile(mode="w", suffix=".json", delete=False, encoding="utf-8") as f:
            path = Path(f.name)
        try:
            _RENDERER.write(_unicode_report(), path)
            content = path.read_bytes()
            assert "Caf\u00e9".encode("utf-8") in content
        finally:
            path.unlink(missing_ok=True)

    def test_write_deterministic(self) -> None:
        report = _minimal_report()
        with NamedTemporaryFile(mode="w", suffix=".json", delete=False, encoding="utf-8") as f1:
            p1 = Path(f1.name)
        with NamedTemporaryFile(mode="w", suffix=".json", delete=False, encoding="utf-8") as f2:
            p2 = Path(f2.name)
        try:
            _RENDERER.write(report, p1)
            _RENDERER.write(report, p2)
            assert p1.read_text(encoding="utf-8") == p2.read_text(encoding="utf-8")
        finally:
            p1.unlink(missing_ok=True)
            p2.unlink(missing_ok=True)

    def test_write_invalid_path_raises(self) -> None:
        invalid = Path("/nonexistent/directory/report.json")
        with pytest.raises((OSError, FileNotFoundError)):
            _RENDERER.write(_minimal_report(), invalid)

    def test_write_pretty_printed(self) -> None:
        report = _minimal_report()
        with NamedTemporaryFile(mode="w", suffix=".json", delete=False, encoding="utf-8") as f:
            path = Path(f.name)
        try:
            _RENDERER.write(report, path)
            content = path.read_text(encoding="utf-8")
            assert "  " in content
            assert "\n" in content
        finally:
            path.unlink(missing_ok=True)


# ===========================================================================
# Indentation
# ===========================================================================


class TestIndentation:
    def test_four_space_indent(self) -> None:
        result = _RENDERER.render(_minimal_report())
        lines = result.split("\n")
        for line in lines:
            stripped = line.lstrip()
            if stripped and stripped != line:
                indent = len(line) - len(stripped)
                assert indent % 4 == 0, f"Bad indent {indent} on: {line}"

    def test_pretty_printed(self) -> None:
        result = _RENDERER.render(_minimal_report())
        assert result.startswith("{")
        assert result.endswith("}")
        assert "\n" in result
