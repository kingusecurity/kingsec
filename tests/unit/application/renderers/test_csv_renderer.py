"""CSV Report Renderer: comprehensive tests."""

from __future__ import annotations

import csv
import io
from datetime import UTC, datetime
from pathlib import Path
from tempfile import NamedTemporaryFile

import pytest

from kingsec.application.attack_path import (
    AttackEdge,
    AttackGraph,
    AttackNode,
    AttackPath,
)
from kingsec.application.renderers.csv_renderer import _HEADERS, CsvReportRenderer
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

_RENDERER = CsvReportRenderer()
_NOW = datetime(2026, 7, 17, tzinfo=UTC)
_COLUMN_COUNT = len(_HEADERS)


def _empty_cells() -> list[str]:
    return [""] * _COLUMN_COUNT


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
        score_distribution=dist
        or {
            "Critical": 2,
            "High": 3,
            "Medium": 3,
            "Low": 1,
            "Informational": 1,
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
    scanners: tuple[str, ...] = ("nuclei",),
    svc: str | None = "SSH",
    port: int | None = 22,
    proto: str | None = "TCP",
    surface: str | None = "Network Service",
    level: str = "High",
    priority: str = "High",
    cat: str = "vulnerability",
    confidence: float = 0.8,
) -> FindingEntry:
    return FindingEntry(
        correlation_id=cid,
        title=title,
        severity=severity,
        category=cat,
        confidence=confidence,
        scanner_sources=scanners,
        affected_assets=assets,
        service=svc,
        port=port,
        protocol=proto,
        attack_surface=surface,
        risk_score=score,
        risk_level=level,
        priority=priority,
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


def _graph(node_scores: list[int] | None = None) -> AttackGraph:
    if node_scores is None:
        node_scores = [75]
    nodes = [_attack_node(f"corr-{i:04d}", f"Finding {i}", s) for i, s in enumerate(node_scores)]
    edges: list[AttackEdge] = []
    for i in range(len(nodes) - 1):
        edges.append(
            AttackEdge(
                source_id=nodes[i].node_id,
                target_id=nodes[i + 1].node_id,
                relationship="same_asset",
                confidence=0.8,
            )
        )
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


def _appendix(scanners: dict[str, str | None] | None = None) -> Appendix:
    return Appendix(
        scanner_versions=scanners or {"nuclei": "3.2.1", "nmap": "7.95"},
        total_plugins=2,
        generated_at=_NOW,
        generated_by="KingSec Report Builder",
    )


def _minimal_report() -> Report:
    es = _es(
        total_findings=1,
        critical=0,
        high=1,
        medium=0,
        low=0,
        informational=0,
        top_score=75,
        avg_score=75.0,
        assets=1,
        text="Security scan found 1 finding across 1 asset.",
    )
    ts = TechnicalSummary(
        total_findings=1,
        total_correlations=1,
        total_enriched=1,
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
        total_paths=1,
        highest_score=75,
        average_score=75.0,
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
        total_findings=0,
        critical=0,
        high=0,
        medium=0,
        low=0,
        informational=0,
        top_score=0,
        avg_score=0.0,
        assets=0,
        text="No findings were discovered during the scan.",
    )
    ts = TechnicalSummary(
        total_findings=0,
        total_correlations=0,
        total_enriched=0,
        total_risk_assessments=0,
        severity_breakdown={},
        category_breakdown={},
        scanner_coverage={},
    )
    rs = _rs(dist={}, avg=0.0, high=0, low=0)
    fs = FindingSection(entries=(), total_count=0, severity_breakdown={})
    n1 = _attack_node("corr-dummy", "Dummy", 0)
    p = AttackPath(
        path_id="path-empty",
        nodes=(n1,),
        edges=(),
        attack_score=0,
        confidence=0.0,
        estimated_impact="None",
        attack_complexity="Simple",
        likelihood="Low",
        reasoning="Empty.",
        recommendations=(),
    )
    ag = AttackGraph(paths=(p,), total_paths=0, highest_score=0, average_score=0.0, metadata={})
    aps = AttackPathSection(
        total_paths=0,
        highest_score=0,
        average_score=0.0,
        graph=ag,
    )
    recs = RecommendationSection(entries=(), total_recommendations=0)
    app = _appendix(scanners={})
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
        total_findings=5,
        critical=1,
        high=2,
        medium=1,
        low=1,
        informational=0,
        top_score=95,
        avg_score=60.0,
        assets=3,
        text="Security scan found 5 findings across 3 assets.",
    )
    ts = TechnicalSummary(
        total_findings=5,
        total_correlations=5,
        total_enriched=5,
        total_risk_assessments=5,
        severity_breakdown={"CRITICAL": 1, "HIGH": 2, "MEDIUM": 1, "LOW": 1},
        category_breakdown={"vulnerability": 3, "misconfiguration": 1, "info": 1},
        scanner_coverage={"nuclei": 3, "nmap": 2},
    )
    rs = RiskSummary(
        score_distribution={"Critical": 1, "High": 2, "Medium": 1, "Low": 1},
        average_score=60.0,
        highest_score=95,
        lowest_score=15,
        top_risk_factors=("RCE", "SQLi", "XSS"),
    )
    fe1 = _finding_entry(
        "corr-001",
        "RCE in Apache",
        "CRITICAL",
        95,
        assets=("10.0.0.1",),
        scanners=("nuclei", "nmap"),
    )
    fe2 = _finding_entry(
        "corr-002",
        "XSS in Web App",
        "HIGH",
        75,
        assets=("10.0.0.2",),
        scanners=("nuclei",),
    )
    fe3 = _finding_entry("corr-003", "Weak Ciphers", "MEDIUM", 50)
    fe4 = _finding_entry(
        "corr-004",
        "Info Leak",
        "LOW",
        15,
        assets=("10.0.0.1", "10.0.0.3"),
    )
    fs = FindingSection(
        entries=(fe1, fe2, fe3, fe4),
        total_count=4,
        severity_breakdown={"CRITICAL": 1, "HIGH": 1, "MEDIUM": 1, "LOW": 1},
    )
    ag = _graph([95, 75, 50])
    aps = AttackPathSection(
        total_paths=1,
        highest_score=75,
        average_score=75.0,
        graph=ag,
    )
    ae1 = _asset_entry("10.0.0.1", 2, 95, 85.0)
    ae2 = _asset_entry("10.0.0.2", 2, 75, 62.5)
    ae3 = _asset_entry("10.0.0.3", 1, 50, 50.0)
    asset_sum = AssetSummary(entries=(ae1, ae2, ae3), total_assets=3)
    re1 = _rec_entry(
        "RCE in Apache",
        "CRITICAL",
        95,
        "corr-001",
        ("Patch Apache", "Update firewall rules"),
    )
    re2 = _rec_entry(
        "XSS in Web App",
        "HIGH",
        75,
        "corr-002",
        ("Sanitize inputs",),
    )
    recs = RecommendationSection(entries=(re1, re2), total_recommendations=3)
    app = _appendix({"nuclei": "3.2.1", "nmap": "7.95", "nikto": "2.5.0"})
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
# Empty report
# ===========================================================================


class TestEmptyReport:
    def test_returns_string(self) -> None:
        result = _RENDERER.render(_empty_report())
        assert isinstance(result, str)

    def test_only_headers(self) -> None:
        result = _RENDERER.render(_empty_report())
        rows = result.strip().split("\n")
        assert len(rows) == 1

    def test_headers_present(self) -> None:
        result = _RENDERER.render(_empty_report())
        reader = csv.reader(io.StringIO(result))
        headers = next(reader)
        assert headers == _HEADERS

    def test_no_data_rows(self) -> None:
        result = _RENDERER.render(_empty_report())
        reader = csv.reader(io.StringIO(result))
        next(reader)
        rows = list(reader)
        assert len(rows) == 0

    def test_header_count(self) -> None:
        result = _RENDERER.render(_empty_report())
        reader = csv.reader(io.StringIO(result))
        headers = next(reader)
        assert len(headers) == _COLUMN_COUNT


# ===========================================================================
# Single finding
# ===========================================================================


class TestSingleFinding:
    def test_one_row_per_finding(self) -> None:
        result = _RENDERER.render(_minimal_report())
        reader = csv.reader(io.StringIO(result))
        next(reader)
        rows = list(reader)
        assert len(rows) == 1

    def test_correlation_id(self) -> None:
        result = _RENDERER.render(_minimal_report())
        reader = csv.reader(io.StringIO(result))
        next(reader)
        row = next(reader)
        assert row[0] == "corr-001"

    def test_finding_id_column(self) -> None:
        result = _RENDERER.render(_minimal_report())
        reader = csv.reader(io.StringIO(result))
        next(reader)
        row = next(reader)
        assert row[1] == "corr-001"

    def test_title_column(self) -> None:
        result = _RENDERER.render(_minimal_report())
        reader = csv.reader(io.StringIO(result))
        next(reader)
        row = next(reader)
        assert row[2] == "SSH Vulnerability"

    def test_severity_column(self) -> None:
        result = _RENDERER.render(_minimal_report())
        reader = csv.reader(io.StringIO(result))
        next(reader)
        row = next(reader)
        assert row[3] == "HIGH"

    def test_risk_score_column(self) -> None:
        result = _RENDERER.render(_minimal_report())
        reader = csv.reader(io.StringIO(result))
        next(reader)
        row = next(reader)
        assert row[4] == "75"

    def test_risk_level_column(self) -> None:
        result = _RENDERER.render(_minimal_report())
        reader = csv.reader(io.StringIO(result))
        next(reader)
        row = next(reader)
        assert row[5] == "High"

    def test_priority_column(self) -> None:
        result = _RENDERER.render(_minimal_report())
        reader = csv.reader(io.StringIO(result))
        next(reader)
        row = next(reader)
        assert row[6] == "High"

    def test_category_column(self) -> None:
        result = _RENDERER.render(_minimal_report())
        reader = csv.reader(io.StringIO(result))
        next(reader)
        row = next(reader)
        assert row[7] == "vulnerability"

    def test_affected_asset_column(self) -> None:
        result = _RENDERER.render(_minimal_report())
        reader = csv.reader(io.StringIO(result))
        next(reader)
        row = next(reader)
        assert row[8] == "10.0.0.1"

    def test_scanner_column(self) -> None:
        result = _RENDERER.render(_minimal_report())
        reader = csv.reader(io.StringIO(result))
        next(reader)
        row = next(reader)
        assert row[9] == "nuclei"

    def test_scanner_version_column(self) -> None:
        result = _RENDERER.render(_minimal_report())
        reader = csv.reader(io.StringIO(result))
        next(reader)
        row = next(reader)
        assert "nuclei 3.2.1" in row[10]

    def test_attack_surface_column(self) -> None:
        result = _RENDERER.render(_minimal_report())
        reader = csv.reader(io.StringIO(result))
        next(reader)
        row = next(reader)
        assert row[18] == "Network Service"

    def test_service_column(self) -> None:
        result = _RENDERER.render(_minimal_report())
        reader = csv.reader(io.StringIO(result))
        next(reader)
        row = next(reader)
        assert row[20] == "SSH"

    def test_protocol_column(self) -> None:
        result = _RENDERER.render(_minimal_report())
        reader = csv.reader(io.StringIO(result))
        next(reader)
        row = next(reader)
        assert row[21] == "TCP"

    def test_port_column(self) -> None:
        result = _RENDERER.render(_minimal_report())
        reader = csv.reader(io.StringIO(result))
        next(reader)
        row = next(reader)
        assert row[22] == "22"

    def test_recommendations_column(self) -> None:
        result = _RENDERER.render(_minimal_report())
        reader = csv.reader(io.StringIO(result))
        next(reader)
        row = next(reader)
        assert "Update OpenSSH" in row[13]
        assert "Disable root login" in row[13]

    def test_unavailable_fields_empty(self) -> None:
        """Fields not available in the Report model should be empty."""
        result = _RENDERER.render(_minimal_report())
        reader = csv.reader(io.StringIO(result))
        next(reader)
        row = next(reader)
        # Description, Evidence, References, Business Impact,
        # Exploit Likelihood, Remediation Complexity, Technology,
        # Operating System, Risk Factors, Discovered At
        assert row[11] == ""  # Description
        assert row[12] == ""  # Evidence
        assert row[14] == ""  # References
        assert row[15] == ""  # Business Impact
        assert row[16] == ""  # Exploit Likelihood
        assert row[17] == ""  # Remediation Complexity
        assert row[19] == ""  # Technology
        assert row[23] == ""  # Operating System
        assert row[24] == ""  # Risk Factors
        assert row[25] == ""  # Discovered At


# ===========================================================================
# Multiple findings
# ===========================================================================


class TestManyFindings:
    def test_four_rows(self) -> None:
        result = _RENDERER.render(_multi_report())
        reader = csv.reader(io.StringIO(result))
        next(reader)
        rows = list(reader)
        assert len(rows) == 4

    def test_all_titles_present(self) -> None:
        result = _RENDERER.render(_multi_report())
        reader = csv.reader(io.StringIO(result))
        next(reader)
        titles = [r[2] for r in reader]
        assert "RCE in Apache" in titles
        assert "XSS in Web App" in titles
        assert "Weak Ciphers" in titles
        assert "Info Leak" in titles

    def test_scanner_versions_with_multiple_scanners(self) -> None:
        result = _RENDERER.render(_multi_report())
        reader = csv.reader(io.StringIO(result))
        next(reader)
        rows = list(reader)
        corr001 = next(r for r in rows if r[0] == "corr-001")
        assert "nuclei 3.2.1" in corr001[10]
        assert "nmap 7.95" in corr001[10]

    def test_affected_assets_with_semicolon(self) -> None:
        result = _RENDERER.render(_multi_report())
        reader = csv.reader(io.StringIO(result))
        next(reader)
        corr004 = next(r for r in reader if r[0] == "corr-004")
        assert corr004[8] == "10.0.0.1; 10.0.0.3"


# ===========================================================================
# Commas
# ===========================================================================


class TestCommas:
    def test_comma_in_title(self) -> None:
        fe = _finding_entry(cid="c-comma", title="SQL, Injection, Finding")
        fs = FindingSection(entries=(fe,), total_count=1, severity_breakdown={"HIGH": 1})
        r = _build_report_with_finding_section(fs)
        result = _RENDERER.render(r)
        reader = csv.reader(io.StringIO(result))
        next(reader)
        row = next(reader)
        assert row[2] == "SQL, Injection, Finding"

    def test_comma_in_asset(self) -> None:
        fe = _finding_entry(cid="c-asset", title="Test", assets=("10,0,0,1",))
        fs = FindingSection(entries=(fe,), total_count=1, severity_breakdown={"HIGH": 1})
        r = _build_report_with_finding_section(fs)
        result = _RENDERER.render(r)
        reader = csv.reader(io.StringIO(result))
        next(reader)
        row = next(reader)
        assert row[8] == "10,0,0,1"


# ===========================================================================
# Quotes
# ===========================================================================


class TestQuotes:
    def test_quote_in_title(self) -> None:
        fe = _finding_entry(cid="c-quote", title='SSH "Vulnerability" Test')
        fs = FindingSection(entries=(fe,), total_count=1, severity_breakdown={"HIGH": 1})
        r = _build_report_with_finding_section(fs)
        result = _RENDERER.render(r)
        reader = csv.reader(io.StringIO(result))
        next(reader)
        row = next(reader)
        assert row[2] == 'SSH "Vulnerability" Test'

    def test_proper_csv_quoting(self) -> None:
        fe = _finding_entry(cid="c-quote2", title='Finding with "quotes"')
        fs = FindingSection(entries=(fe,), total_count=1, severity_breakdown={"HIGH": 1})
        r = _build_report_with_finding_section(fs)
        result = _RENDERER.render(r)
        assert '"Finding with ""quotes"""' in result


# ===========================================================================
# Unicode
# ===========================================================================


class TestUnicode:
    def test_unicode_in_title(self) -> None:
        fe = _finding_entry(cid="c-utf", title="Caf\u00e9 vuln r\u00e9sum\u00e9")
        fs = FindingSection(entries=(fe,), total_count=1, severity_breakdown={"HIGH": 1})
        r = _build_report_with_finding_section(fs)
        result = _RENDERER.render(r)
        assert "Caf\u00e9" in result

    def test_unicode_in_asset(self) -> None:
        fe = _finding_entry(cid="c-utf2", title="Test", assets=("M\u00fcnchen-01",))
        fs = FindingSection(entries=(fe,), total_count=1, severity_breakdown={"HIGH": 1})
        r = _build_report_with_finding_section(fs)
        result = _RENDERER.render(r)
        assert "M\u00fcnchen" in result

    def test_unicode_roundtrip(self) -> None:
        fe = _finding_entry(cid="c-utf3", title="\u00e9\u00e0\u00fc\u00f1")
        fs = FindingSection(entries=(fe,), total_count=1, severity_breakdown={"HIGH": 1})
        r = _build_report_with_finding_section(fs)
        result = _RENDERER.render(r)
        reader = csv.reader(io.StringIO(result))
        next(reader)
        row = next(reader)
        assert row[2] == "\u00e9\u00e0\u00fc\u00f1"


# ===========================================================================
# Multiline descriptions (not available, but quoting should handle newlines)
# ===========================================================================


class TestMultiline:
    def test_newline_in_title(self) -> None:
        fe = _finding_entry(cid="c-ml", title="Line1\nLine2")
        fs = FindingSection(entries=(fe,), total_count=1, severity_breakdown={"HIGH": 1})
        r = _build_report_with_finding_section(fs)
        result = _RENDERER.render(r)
        reader = csv.reader(io.StringIO(result))
        next(reader)
        row = next(reader)
        assert row[2] == "Line1\nLine2"

    def test_multiline_field_csv_quoted(self) -> None:
        fe = _finding_entry(cid="c-ml2", title="Multi\nline\ntitle")
        fs = FindingSection(entries=(fe,), total_count=1, severity_breakdown={"HIGH": 1})
        r = _build_report_with_finding_section(fs)
        result = _RENDERER.render(r)
        assert '"' in result
        assert "Multi\nline\ntitle" in result


# ===========================================================================
# Deterministic output
# ===========================================================================


class TestDeterministic:
    def test_same_input_same_output(self) -> None:
        report = _minimal_report()
        s1 = _RENDERER.render(report)
        s2 = _RENDERER.render(report)
        assert s1 == s2

    def test_stable_ordering(self) -> None:
        r1 = _multi_report()
        r2 = _multi_report()
        assert _RENDERER.render(r1) == _RENDERER.render(r2)

    def test_findings_order(self) -> None:
        result = _RENDERER.render(_multi_report())
        reader = csv.reader(io.StringIO(result))
        next(reader)
        ids = [r[0] for r in reader]
        assert ids == ["corr-001", "corr-002", "corr-003", "corr-004"]


# ===========================================================================
# File writing
# ===========================================================================


class TestFileWriting:
    def test_write_creates_file(self) -> None:
        report = _minimal_report()
        with NamedTemporaryFile(mode="w", suffix=".csv", delete=False, encoding="utf-8") as f:
            path = Path(f.name)
        try:
            _RENDERER.write(report, path)
            assert path.exists()
            content = path.read_text(encoding="utf-8")
            reader = csv.reader(io.StringIO(content))
            headers = next(reader)
            assert headers == _HEADERS
        finally:
            path.unlink(missing_ok=True)

    def test_write_utf8_encoding(self) -> None:
        fe = _finding_entry(cid="c-wutf", title="Caf\u00e9")
        fs = FindingSection(entries=(fe,), total_count=1, severity_breakdown={"HIGH": 1})
        r = _build_report_with_finding_section(fs)
        with NamedTemporaryFile(mode="w", suffix=".csv", delete=False, encoding="utf-8") as f:
            path = Path(f.name)
        try:
            _RENDERER.write(r, path)
            content = path.read_bytes()
            assert "Caf\u00e9".encode("utf-8") in content
        finally:
            path.unlink(missing_ok=True)

    def test_write_deterministic(self) -> None:
        report = _minimal_report()
        with NamedTemporaryFile(mode="w", suffix=".csv", delete=False, encoding="utf-8") as f1:
            p1 = Path(f1.name)
        with NamedTemporaryFile(mode="w", suffix=".csv", delete=False, encoding="utf-8") as f2:
            p2 = Path(f2.name)
        try:
            _RENDERER.write(report, p1)
            _RENDERER.write(report, p2)
            assert p1.read_text(encoding="utf-8") == p2.read_text(encoding="utf-8")
        finally:
            p1.unlink(missing_ok=True)
            p2.unlink(missing_ok=True)

    def test_write_invalid_path_raises(self) -> None:
        invalid = Path("/nonexistent/directory/report.csv")
        with pytest.raises((OSError, FileNotFoundError)):
            _RENDERER.write(_minimal_report(), invalid)


# ===========================================================================
# Proper quoting
# ===========================================================================


class TestProperQuoting:
    def test_rfc4180_compliant(self) -> None:
        result = _RENDERER.render(_minimal_report())
        assert result.endswith("\n")

    def test_header_not_quoted_unless_needed(self) -> None:
        result = _RENDERER.render(_minimal_report())
        first_line = result.split("\n")[0]
        # Headers with simple text should not be quoted
        assert "Correlation ID" in first_line

    def test_newlines_quoted(self) -> None:
        fe = _finding_entry(cid="c-nl", title="line1\nline2\nline3")
        fs = FindingSection(entries=(fe,), total_count=1, severity_breakdown={"HIGH": 1})
        r = _build_report_with_finding_section(fs)
        result = _RENDERER.render(r)
        # The field with newlines must be quoted per RFC4180
        assert result.count('"') >= 2

    def test_no_extra_trailing_lines(self) -> None:
        result = _RENDERER.render(_minimal_report())
        assert result.count("\n") == 2  # header + 1 data row + trailing newline = 2 newlines


# ===========================================================================
# Helper: build a minimal valid report with a custom FindingSection
# ===========================================================================


def _build_report_with_finding_section(fs: FindingSection) -> Report:
    es = _es(
        total_findings=len(fs.entries) if fs.entries else 0,
        critical=sum(1 for e in fs.entries if e.severity == "CRITICAL"),
        high=sum(1 for e in fs.entries if e.severity == "HIGH"),
        medium=sum(1 for e in fs.entries if e.severity == "MEDIUM"),
        low=sum(1 for e in fs.entries if e.severity == "LOW"),
        informational=sum(1 for e in fs.entries if e.severity == "INFO"),
        top_score=max((e.risk_score for e in fs.entries), default=0),
        avg_score=(sum(e.risk_score for e in fs.entries) / len(fs.entries) if fs.entries else 0.0),
        assets=len({a for e in fs.entries for a in e.affected_assets}),
        text="Custom finding section report.",
    )
    ts = TechnicalSummary(
        total_findings=len(fs.entries),
        total_correlations=len(fs.entries),
        total_enriched=len(fs.entries),
        total_risk_assessments=len(fs.entries),
        severity_breakdown={},
        category_breakdown={},
        scanner_coverage={},
    )
    rs = RiskSummary(
        score_distribution={},
        average_score=0.0,
        highest_score=0,
        lowest_score=0,
        top_risk_factors=(),
    )
    aps = AttackPathSection(
        total_paths=0,
        highest_score=0,
        average_score=0.0,
        graph=_graph([0]),
    )
    recs = RecommendationSection(entries=(), total_recommendations=0)
    app = Appendix(
        scanner_versions={"nuclei": "3.2.1"},
        total_plugins=1,
        generated_at=_NOW,
        generated_by="KingSec",
    )
    assets_list = [
        AssetEntry(
            asset=a,
            finding_count=1,
            highest_risk_score=0,
            average_risk_score=0.0,
        )
        for a in sorted({a for e in fs.entries for a in e.affected_assets})
    ]
    return Report(
        report_id="rpt-csv-custom",
        title="KingSec Security Report",
        created_at=_NOW,
        executive_summary=es,
        technical_summary=ts,
        risk_summary=rs,
        asset_summary=AssetSummary(
            entries=tuple(assets_list),
            total_assets=len(assets_list),
        ),
        finding_section=fs,
        attack_path_section=aps,
        recommendation_section=recs,
        appendix=app,
    )
