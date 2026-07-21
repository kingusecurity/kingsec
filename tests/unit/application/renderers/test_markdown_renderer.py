"""Markdown Report Renderer: comprehensive tests."""

from __future__ import annotations

from datetime import UTC, datetime
from pathlib import Path
from tempfile import NamedTemporaryFile

from kingsec.application.attack_path import (
    AttackEdge,
    AttackGraph,
    AttackNode,
    AttackPath,
)
from kingsec.application.renderers import MarkdownReportRenderer
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

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

_RENDERER = MarkdownReportRenderer()
_NOW = datetime(2026, 7, 17, tzinfo=UTC)


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
        score_distribution=dist or {"Critical": 2, "High": 3, "Medium": 3, "Low": 1, "Informational": 1},
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
) -> FindingEntry:
    return FindingEntry(
        correlation_id=cid,
        title=title,
        severity=severity,
        category="vulnerability",
        confidence=0.8,
        scanner_sources=("nuclei",),
        affected_assets=("10.0.0.1",),
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
    nodes = [_attack_node(f"corr-{i:04d}", f"Finding {i}", s)
             for i, s in enumerate(node_scores)]
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
    es = _es(total_findings=1, critical=0, high=1, medium=0, low=0, informational=0,
             top_score=75, avg_score=75.0, assets=1,
             text="Security scan found 1 finding across 1 asset.")
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
    es = _es(total_findings=0, critical=0, high=0, medium=0, low=0, informational=0,
             top_score=0, avg_score=0.0, assets=0,
             text="No findings were discovered during the scan.")
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
    es = _es(total_findings=5, critical=1, high=2, medium=1, low=1, informational=0,
             top_score=95, avg_score=60.0, assets=3,
             text="Security scan found 5 findings across 3 assets.")
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
    fe2 = _finding_entry("corr-002", "XSS in Web App", "HIGH", 75)
    fe3 = _finding_entry("corr-003", "Weak Ciphers", "MEDIUM", 50)
    fe4 = _finding_entry("corr-004", "Info Leak", "LOW", 15)
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
    re1 = _rec_entry("RCE in Apache", "CRITICAL", 95, "corr-001",
                     ("Patch Apache", "Update firewall rules"))
    re2 = _rec_entry("XSS in Web App", "HIGH", 75, "corr-002",
                     ("Sanitize inputs",))
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


# ===========================================================================
# Basic rendering
# ===========================================================================


class TestBasicRendering:
    def test_returns_string(self) -> None:
        md = _RENDERER.render(_minimal_report())
        assert isinstance(md, str)

    def test_starts_with_title(self) -> None:
        md = _RENDERER.render(_minimal_report())
        assert md.startswith("# KingSec Security Report")

    def test_contains_generation_timestamp(self) -> None:
        md = _RENDERER.render(_minimal_report())
        assert "Generated" in md
        assert "UTC" in md

    def test_uses_unix_newlines(self) -> None:
        md = _RENDERER.render(_minimal_report())
        assert "\r\n" not in md

    def test_no_trailing_whitespace(self) -> None:
        md = _RENDERER.render(_minimal_report())
        for line in md.split("\n"):
            assert line == line.rstrip(), f"Line has trailing whitespace: {line!r}"

    def test_utf8_compatibility(self) -> None:
        es = _es(text="Résumé with émoji 🛡️")
        fe = _finding_entry(title="Café & Füße")
        fs = FindingSection(entries=(fe,), total_count=1, severity_breakdown={"HIGH": 1})
        ae = _asset_entry(asset="München-01")
        a_s = AssetSummary(entries=(ae,), total_assets=1)
        re = _rec_entry(title="Café Issue", recs=("Fix café",))
        rec_s = RecommendationSection(entries=(re,), total_recommendations=1)
        app = Appendix(
            scanner_versions={"nuclei🚀": "3.0"},
            total_plugins=1, generated_at=_NOW,
            generated_by="KingSec",
        )
        ts = TechnicalSummary(
            total_findings=1, total_correlations=1, total_enriched=1,
            total_risk_assessments=1,
            severity_breakdown={"HIGH": 1}, category_breakdown={"vuln": 1},
            scanner_coverage={"nuclei": 1},
        )
        rs = _rs(dist={"High": 1}, avg=75.0, high=75, low=75)
        aps = AttackPathSection(
            total_paths=1, highest_score=75, average_score=75.0,
            graph=_graph(),
        )
        r = Report(
            report_id="rpt-utf", title="UTF-8 Test", created_at=_NOW,
            executive_summary=es, technical_summary=ts, risk_summary=rs,
            asset_summary=a_s,
            finding_section=fs, attack_path_section=aps,
            recommendation_section=rec_s, appendix=app,
        )
        md = _RENDERER.render(r)
        assert "Résumé" in md
        assert "Café" in md
        assert "München" in md
        assert "nuclei🚀" in md


# ===========================================================================
# Empty report
# ===========================================================================


class TestEmptyReport:
    def test_render_empty(self) -> None:
        md = _RENDERER.render(_empty_report())
        assert "# KingSec Security Report" in md

    def test_empty_no_findings_text(self) -> None:
        md = _RENDERER.render(_empty_report())
        assert "No findings" in md

    def test_empty_no_attack_paths(self) -> None:
        md = _RENDERER.render(_empty_report())
        assert "No attack paths identified" in md

    def test_empty_no_assets(self) -> None:
        md = _RENDERER.render(_empty_report())
        assert "No assets identified" in md

    def test_empty_no_recommendations(self) -> None:
        md = _RENDERER.render(_empty_report())
        assert "No recommendations available" in md

    def test_empty_has_appendix(self) -> None:
        md = _RENDERER.render(_empty_report())
        assert "## Appendix" in md

    def test_empty_has_metadata_when_no_scanners(self) -> None:
        md = _RENDERER.render(_empty_report())
        assert "**Total scanners:** 0" in md


# ===========================================================================
# Heading structure
# ===========================================================================


class TestHeadingStructure:
    def test_has_h1_title(self) -> None:
        md = _RENDERER.render(_minimal_report())
        assert md.startswith("# ")

    def test_has_executive_summary_h2(self) -> None:
        md = _RENDERER.render(_minimal_report())
        assert "## Executive Summary" in md

    def test_has_risk_summary_h2(self) -> None:
        md = _RENDERER.render(_minimal_report())
        assert "## Risk Summary" in md

    def test_has_technical_findings_h2(self) -> None:
        md = _RENDERER.render(_minimal_report())
        assert "## Technical Findings" in md

    def test_has_attack_paths_h2(self) -> None:
        md = _RENDERER.render(_minimal_report())
        assert "## Attack Paths" in md

    def test_has_assets_h2(self) -> None:
        md = _RENDERER.render(_minimal_report())
        assert "## Assets" in md

    def test_has_recommendations_h2(self) -> None:
        md = _RENDERER.render(_minimal_report())
        assert "## Recommendations" in md

    def test_has_appendix_h2(self) -> None:
        md = _RENDERER.render(_minimal_report())
        assert "## Appendix" in md

    def test_finding_has_h3(self) -> None:
        md = _RENDERER.render(_minimal_report())
        assert "### SSH Vulnerability" in md


# ===========================================================================
# Table formatting
# ===========================================================================


class TestTableFormatting:
    def test_executive_summary_has_tables(self) -> None:
        md = _RENDERER.render(_minimal_report())
        assert "| Severity | Count |" in md
        assert "| Critical |" in md
        assert "| High     |" in md

    def test_risk_summary_has_tables(self) -> None:
        md = _RENDERER.render(_minimal_report())
        assert "| Average Score |" in md
        assert "| Highest Score |" in md

    def test_finding_has_field_table(self) -> None:
        md = _RENDERER.render(_minimal_report())
        assert "| **Severity** |" in md
        assert "| **Risk Score** |" in md

    def test_assets_has_table(self) -> None:
        md = _RENDERER.render(_minimal_report())
        assert "| Asset | Findings |" in md

    def test_attack_path_nodes_table(self) -> None:
        md = _RENDERER.render(_minimal_report())
        assert "| # | Title | Severity |" in md

    def test_recommendation_has_table(self) -> None:
        md = _RENDERER.render(_minimal_report())
        assert "| **Severity** |" in md


# ===========================================================================
# Bullet formatting
# ===========================================================================


class TestBulletFormatting:
    def test_risk_factors_as_bullets(self) -> None:
        md = _RENDERER.render(_minimal_report())
        assert "- Remote Code Execution" in md
        assert "- SQL Injection" in md

    def test_recommendation_actions_as_bullets(self) -> None:
        md = _RENDERER.render(_minimal_report())
        assert "- Update OpenSSH" in md
        assert "- Disable root login" in md


# ===========================================================================
# Multi-finding report
# ===========================================================================


class TestMultiReport:
    def test_all_findings_present(self) -> None:
        md = _RENDERER.render(_multi_report())
        assert "RCE in Apache" in md
        assert "XSS in Web App" in md
        assert "Weak Ciphers" in md

    def test_all_assets_present(self) -> None:
        md = _RENDERER.render(_multi_report())
        assert "10.0.0.1" in md
        assert "10.0.0.2" in md
        assert "10.0.0.3" in md

    def test_all_recommendations_present(self) -> None:
        md = _RENDERER.render(_multi_report())
        assert "Patch Apache" in md
        assert "Sanitize inputs" in md

    def test_scanner_versions_table(self) -> None:
        md = _RENDERER.render(_multi_report())
        assert "nuclei" in md
        assert "nmap" in md
        assert "nikto" in md


# ===========================================================================
# Attack paths
# ===========================================================================


class TestAttackPaths:
    def test_path_id_displayed(self) -> None:
        md = _RENDERER.render(_minimal_report())
        assert "path-001" in md

    def test_path_score_displayed(self) -> None:
        md = _RENDERER.render(_minimal_report())
        assert "Attack Score" in md

    def test_path_nodes_displayed(self) -> None:
        md = _RENDERER.render(_minimal_report())
        assert "SSH Vuln" in md

    def test_path_reasoning_displayed(self) -> None:
        md = _RENDERER.render(_minimal_report())
        assert "Attack chain detected" in md


# ===========================================================================
# Deterministic output
# ===========================================================================


class TestDeterministic:
    def test_same_input_same_output(self) -> None:
        report = _minimal_report()
        md1 = _RENDERER.render(report)
        md2 = _RENDERER.render(report)
        assert md1 == md2

    def test_stable_ordering(self) -> None:
        r1 = _multi_report()
        r2 = _multi_report()
        assert _RENDERER.render(r1) == _RENDERER.render(r2)


# ===========================================================================
# File writing
# ===========================================================================


class TestFileWriting:
    def test_write_creates_file(self) -> None:
        report = _minimal_report()
        with NamedTemporaryFile(mode="w", suffix=".md", delete=False, encoding="utf-8") as f:
            path = Path(f.name)
        try:
            _RENDERER.write(report, path)
            assert path.exists()
            content = path.read_text(encoding="utf-8")
            assert "# KingSec Security Report" in content
        finally:
            path.unlink(missing_ok=True)

    def test_write_utf8_encoding(self) -> None:
        es = _es(text="Résumé")
        fe = _finding_entry(title="Café")
        fs = FindingSection(entries=(fe,), total_count=1, severity_breakdown={"HIGH": 1})
        ae = _asset_entry()
        a_s = AssetSummary(entries=(ae,), total_assets=1)
        re = _rec_entry(recs=("Fix café",))
        rec_s = RecommendationSection(entries=(re,), total_recommendations=1)
        ts = TechnicalSummary(
            total_findings=1, total_correlations=1, total_enriched=1,
            total_risk_assessments=1,
            severity_breakdown={"HIGH": 1}, category_breakdown={"vuln": 1},
            scanner_coverage={"x": 1},
        )
        rs = _rs(dist={"High": 1}, avg=75.0, high=75, low=75)
        aps = AttackPathSection(total_paths=1, highest_score=75, average_score=75.0, graph=_graph())
        app = Appendix(scanner_versions={"n": "1"}, total_plugins=1, generated_at=_NOW, generated_by="KS")
        r = Report(
            report_id="rpt-w", title="UTF-8", created_at=_NOW,
            executive_summary=es, technical_summary=ts, risk_summary=rs,
            asset_summary=a_s, finding_section=fs, attack_path_section=aps,
            recommendation_section=rec_s, appendix=app,
        )
        with NamedTemporaryFile(mode="w", suffix=".md", delete=False, encoding="utf-8") as f:
            path = Path(f.name)
        try:
            _RENDERER.write(r, path)
            content = path.read_text(encoding="utf-8")
            assert "Résumé" in content
            assert "Café" in content
        finally:
            path.unlink(missing_ok=True)


# ===========================================================================
# Idempotency
# ===========================================================================


class TestIdempotency:
    def test_render_twice_identical(self) -> None:
        report = _minimal_report()
        md1 = _RENDERER.render(report)
        md2 = _RENDERER.render(report)
        assert md1 == md2

    def test_write_twice_identical_content(self) -> None:
        report = _minimal_report()
        with NamedTemporaryFile(mode="w", suffix=".md", delete=False, encoding="utf-8") as f1:
            p1 = Path(f1.name)
        with NamedTemporaryFile(mode="w", suffix=".md", delete=False, encoding="utf-8") as f2:
            p2 = Path(f2.name)
        try:
            _RENDERER.write(report, p1)
            _RENDERER.write(report, p2)
            assert p1.read_text(encoding="utf-8") == p2.read_text(encoding="utf-8")
        finally:
            p1.unlink(missing_ok=True)
            p2.unlink(missing_ok=True)


# ===========================================================================
# Edge cases
# ===========================================================================


class TestEdgeCases:
    def test_no_top_risk_factors(self) -> None:
        rs = RiskSummary(
            score_distribution={"High": 1},
            average_score=75.0, highest_score=75, lowest_score=75,
            top_risk_factors=(),
        )
        ts = TechnicalSummary(
            total_findings=1, total_correlations=1, total_enriched=1,
            total_risk_assessments=1,
            severity_breakdown={"HIGH": 1}, category_breakdown={}, scanner_coverage={},
        )
        fe = _finding_entry()
        fs = FindingSection(entries=(fe,), total_count=1, severity_breakdown={"HIGH": 1})
        ae = _asset_entry()
        a_s = AssetSummary(entries=(ae,), total_assets=1)
        app = Appendix(scanner_versions={"n": "1"}, total_plugins=1, generated_at=_NOW, generated_by="KS")
        aps = AttackPathSection(total_paths=0, highest_score=0, average_score=0.0, graph=_graph([0]))
        recs = RecommendationSection(entries=(), total_recommendations=0)
        r = Report(
            report_id="rpt-e", title="Edge", created_at=_NOW,
            executive_summary=_es(total_findings=1), technical_summary=ts,
            risk_summary=rs, asset_summary=a_s, finding_section=fs,
            attack_path_section=aps, recommendation_section=recs, appendix=app,
        )
        md = _RENDERER.render(r)
        assert "## Risk Summary" in md
        assert "## Technical Findings" in md

    def test_nullable_finding_fields(self) -> None:
        fe = FindingEntry(
            correlation_id="c-1", title="Test", severity="LOW",
            category="info", confidence=0.3,
            scanner_sources=(), affected_assets=(),
            service=None, port=None, protocol=None,
            attack_surface=None, risk_score=0,
            risk_level="Low", priority="None",
        )
        fs = FindingSection(entries=(fe,), total_count=1, severity_breakdown={"LOW": 1})
        es = _es(total_findings=1, critical=0, high=0, medium=0, low=1, informational=0)
        ts = TechnicalSummary(
            total_findings=1, total_correlations=1, total_enriched=1,
            total_risk_assessments=1,
            severity_breakdown={"LOW": 1}, category_breakdown={"info": 1},
            scanner_coverage={},
        )
        rs = _rs(dist={"Low": 1}, avg=0.0, high=0, low=0)
        ae = _asset_entry("10.0.0.1", 1, 0, 0.0)
        a_s = AssetSummary(entries=(ae,), total_assets=1)
        app = Appendix(scanner_versions={"n": "1"}, total_plugins=1, generated_at=_NOW, generated_by="KS")
        n1 = _attack_node("c-1", "Test", 0)
        p = AttackPath(path_id="path-e", nodes=(n1,), edges=(),
                       attack_score=0, confidence=0.0,
                       estimated_impact="None", attack_complexity="Simple",
                       likelihood="Low", reasoning=".", recommendations=())
        ag = AttackGraph(paths=(p,), total_paths=1, highest_score=0,
                         average_score=0.0, metadata={})
        aps = AttackPathSection(total_paths=0, highest_score=0, average_score=0.0, graph=ag)
        recs = RecommendationSection(entries=(), total_recommendations=0)
        r = Report(
            report_id="rpt-null", title="Null Fields", created_at=_NOW,
            executive_summary=es, technical_summary=ts, risk_summary=rs,
            asset_summary=a_s, finding_section=fs, attack_path_section=aps,
            recommendation_section=recs, appendix=app,
        )
        md = _RENDERER.render(r)
        assert "N/A" in md
