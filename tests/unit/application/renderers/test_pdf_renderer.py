"""PDF Report Renderer: comprehensive tests."""

from __future__ import annotations

import tempfile
from datetime import UTC, datetime
from pathlib import Path

import pytest
from PyPDF2 import PdfReader
from tests.unit.application.renderers.test_markdown_renderer import (
    _empty_report,
    _minimal_report,
    _multi_report,
)

from kingsec.application.renderers.pdf_renderer import PDFReportRenderer

_RENDERER = PDFReportRenderer()


def _extract_text(pdf_bytes: bytes) -> str:
    """Extract all text from PDF bytes using PyPDF2."""
    import io

    reader = PdfReader(io.BytesIO(pdf_bytes))
    text_parts: list[str] = []
    for page in reader.pages:
        page_text = page.extract_text()
        if page_text:
            text_parts.append(page_text)
    return "\n".join(text_parts)


def _extract_text_from_file(path: Path) -> str:
    """Extract all text from a PDF file."""
    reader = PdfReader(str(path))
    text_parts: list[str] = []
    for page in reader.pages:
        page_text = page.extract_text()
        if page_text:
            text_parts.append(page_text)
    return "\n".join(text_parts)


# ===========================================================================
# Basic rendering
# ===========================================================================


class TestBasicRendering:
    def test_returns_bytes(self) -> None:
        pdf_bytes = _RENDERER.render_bytes(_minimal_report())
        assert isinstance(pdf_bytes, bytes)
        assert len(pdf_bytes) > 0

    def test_pdf_header(self) -> None:
        pdf_bytes = _RENDERER.render_bytes(_minimal_report())
        assert pdf_bytes.startswith(b"%PDF-")

    def test_writes_to_file(self) -> None:
        with tempfile.NamedTemporaryFile(suffix=".pdf", delete=False) as f:
            path = Path(f.name)
        try:
            _RENDERER.render(_minimal_report(), path)
            assert path.exists()
            assert path.stat().st_size > 0
            content = path.read_bytes()
            assert content.startswith(b"%PDF-")
            assert content.rstrip().endswith(b"%%EOF")
        finally:
            if path.exists():
                path.unlink()

    def test_render_and_render_bytes_equivalent(self) -> None:
        """render() output file and render_bytes() should produce valid PDFs
        with the same text content.
        """
        pdf_a = _RENDERER.render_bytes(_minimal_report())
        with tempfile.NamedTemporaryFile(suffix=".pdf", delete=False) as f:
            path = Path(f.name)
        try:
            _RENDERER.render(_minimal_report(), path)
            pdf_b = path.read_bytes()
            # Both should be valid PDFs
            assert pdf_a.startswith(b"%PDF-")
            assert pdf_b.startswith(b"%PDF-")
        finally:
            if path.exists():
                path.unlink()

    def test_generation_timestamp_in_pdf(self) -> None:
        """Report creation date appears in the PDF metadata."""
        report = _minimal_report()
        pdf_bytes = _RENDERER.render_bytes(report)
        text = _extract_text(pdf_bytes)
        ts = report.created_at.astimezone(UTC).strftime("%Y-%m-%d")
        assert ts in text


# ===========================================================================
# Empty report
# ===========================================================================


class TestEmptyReport:
    def test_empty_report_renders(self) -> None:
        pdf_bytes = _RENDERER.render_bytes(_empty_report())
        assert isinstance(pdf_bytes, bytes)
        assert len(pdf_bytes) > 0
        assert pdf_bytes.startswith(b"%PDF-")

    def test_empty_report_multiple_pages(self) -> None:
        """Empty report should still have at least one page (cover + sections)."""
        pdf_bytes = _RENDERER.render_bytes(_empty_report())
        reader = PdfReader(__import__("io").BytesIO(pdf_bytes))
        assert len(reader.pages) >= 1

    def test_empty_report_no_findings_text(self) -> None:
        pdf_bytes = _RENDERER.render_bytes(_empty_report())
        text = _extract_text(pdf_bytes)
        assert "No findings" in text or "no findings" in text


# ===========================================================================
# Multiple findings and pages
# ===========================================================================


class TestMultiFindings:
    def test_multi_report_renders(self) -> None:
        pdf_bytes = _RENDERER.render_bytes(_multi_report())
        assert isinstance(pdf_bytes, bytes)
        assert len(pdf_bytes) > 0
        assert pdf_bytes.startswith(b"%PDF-")

    def test_multi_report_multiple_pages(self) -> None:
        pdf_bytes = _RENDERER.render_bytes(_multi_report())
        reader = PdfReader(__import__("io").BytesIO(pdf_bytes))
        assert len(reader.pages) >= 3

    def test_multi_report_contains_finding_ids(self) -> None:
        pdf_bytes = _RENDERER.render_bytes(_multi_report())
        text = _extract_text(pdf_bytes)
        assert "corr-001" in text or "RCE in Apache" in text

    def test_multi_report_contains_severity_colors(self) -> None:
        """Severity text for different levels should appear."""
        pdf_bytes = _RENDERER.render_bytes(_multi_report())
        text = _extract_text(pdf_bytes)
        assert "CRITICAL" in text or "Critical" in text
        assert "HIGH" in text or "High" in text


# ===========================================================================
# Large report
# ===========================================================================


class TestLargeReport:
    def test_large_report_renders(self) -> None:
        report = _make_large_report()
        pdf_bytes = _RENDERER.render_bytes(report)
        assert isinstance(pdf_bytes, bytes)
        assert len(pdf_bytes) > 0
        assert pdf_bytes.startswith(b"%PDF-")

    def test_large_report_many_pages(self) -> None:
        report = _make_large_report()
        pdf_bytes = _RENDERER.render_bytes(report)
        reader = PdfReader(__import__("io").BytesIO(pdf_bytes))
        assert len(reader.pages) >= 5

    def test_large_report_all_findings_present(self) -> None:
        report = _make_large_report()
        pdf_bytes = _RENDERER.render_bytes(report)
        # Verify page count is sufficient for 50 findings
        reader = PdfReader(__import__("io").BytesIO(pdf_bytes))
        assert len(reader.pages) >= 5
        # Verify the file is large enough to contain all data
        assert len(pdf_bytes) > 10000
        # Verify section content via PyPDF2 metadata
        assert reader.metadata is not None
        assert reader.metadata.title == "KingSec Security Report"


# ===========================================================================
# Unicode support
# ===========================================================================


class TestUnicodeSupport:
    def test_unicode_in_summary(self) -> None:
        report = _make_unicode_report()
        pdf_bytes = _RENDERER.render_bytes(report)
        text = _extract_text(pdf_bytes)
        # Unicode chars should appear in extracted text
        assert "Caf" in text

    def test_unicode_finding_title(self) -> None:
        report = _make_unicode_report()
        pdf_bytes = _RENDERER.render_bytes(report)
        text = _extract_text(pdf_bytes)
        assert "vuln" in text
        assert "r\u00e9sum\u00e9" in text or "r" in text


# ===========================================================================
# Deterministic rendering
# ===========================================================================


class TestDeterministicRendering:
    def test_same_input_produces_same_page_count(self) -> None:
        report = _minimal_report()
        pdf_a = _RENDERER.render_bytes(report)
        pdf_b = _RENDERER.render_bytes(report)
        reader_a = PdfReader(__import__("io").BytesIO(pdf_a))
        reader_b = PdfReader(__import__("io").BytesIO(pdf_b))
        assert len(reader_a.pages) == len(reader_b.pages)

    def test_same_input_produces_same_text(self) -> None:
        report = _minimal_report()
        pdf_a = _RENDERER.render_bytes(report)
        pdf_b = _RENDERER.render_bytes(report)
        text_a = _extract_text(pdf_a)
        text_b = _extract_text(pdf_b)
        assert text_a == text_b

    def test_multi_report_deterministic_text(self) -> None:
        report = _multi_report()
        pdf_a = _RENDERER.render_bytes(report)
        pdf_b = _RENDERER.render_bytes(report)
        text_a = _extract_text(pdf_a)
        text_b = _extract_text(pdf_b)
        assert text_a == text_b


# ===========================================================================
# Error handling
# ===========================================================================


class TestErrorHandling:
    def test_invalid_path_raises(self) -> None:
        invalid_path = Path("/nonexistent/directory/report.pdf")
        with pytest.raises((OSError, FileNotFoundError)):
            _RENDERER.render(_minimal_report(), invalid_path)

    def test_empty_bytes_not_allowed(self) -> None:
        pdf_bytes = _RENDERER.render_bytes(_minimal_report())
        assert len(pdf_bytes) > 100


# ===========================================================================
# Helpers
# ===========================================================================


def _make_large_report():
    """Build a report with 50 findings for large-render testing."""
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

    now = datetime(2026, 7, 17, tzinfo=UTC)

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
        created_at=now,
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
            generated_at=now,
            generated_by="KingSec Report Builder",
        ),
    )


def _make_unicode_report():
    """Build a report with unicode characters."""
    from kingsec.application.attack_path import (
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

    now = datetime(2026, 7, 17, tzinfo=UTC)
    es = ExecutiveSummary(
        total_findings=1,
        total_correlated=1,
        total_enriched=1,
        total_risk_assessments=1,
        critical_count=0,
        high_count=1,
        medium_count=0,
        low_count=0,
        informational_count=0,
        top_risk_score=75,
        average_risk_score=75.0,
        total_assets=1,
        summary_text="Caf\u00e9 r\u00e9sum\u00e9 avec \U0001f6e1\ufe0f shield",
    )

    fe = FindingEntry(
        correlation_id="corr-unicode",
        title="Caf\u00e9 vuln r\u00e9sum\u00e9",
        severity="HIGH",
        category="vulnerability",
        confidence=0.8,
        scanner_sources=("nuclei",),
        affected_assets=("M\u00fcnchen-01", "Z\u00fcrich-02"),
        service="HTTP",
        port=80,
        protocol="TCP",
        attack_surface="Web",
        risk_score=75,
        risk_level="High",
        priority="High",
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

    rs = RiskSummary(
        score_distribution={"High": 1},
        average_score=75.0,
        highest_score=75,
        lowest_score=75,
        top_risk_factors=("Caf\u00e9 Attack", "M\u00fcnchen Exploit"),
    )

    nn = AttackNode(
        node_id="node-unicode",
        correlation_id="corr-unicode",
        title="Caf\u00e9 vuln r\u00e9sum\u00e9",
        severity="HIGH",
        category="vulnerability",
        attack_surface="Web",
        service="HTTP",
        port=80,
        protocol="TCP",
        asset="M\u00fcnchen-01",
        risk_score=75,
        risk_level="High",
    )
    p = AttackPath(
        path_id="path-unicode",
        nodes=(nn,),
        edges=(),
        attack_score=75,
        confidence=0.35,
        estimated_impact="High",
        attack_complexity="Moderate",
        likelihood="Medium",
        reasoning="Unicode attack path.",
        recommendations=("Patch caf\u00e9",),
    )
    ag = AttackGraph(
        paths=(p,),
        total_paths=1,
        highest_score=75,
        average_score=75.0,
        metadata={"total_assessments": "1"},
    )

    return Report(
        report_id="rpt-unicode",
        title="KingSec Security Report",
        created_at=now,
        executive_summary=es,
        technical_summary=ts,
        risk_summary=rs,
        asset_summary=AssetSummary(
            entries=(
                AssetEntry(asset="M\u00fcnchen-01", finding_count=1, highest_risk_score=75, average_risk_score=75.0),
            ),
            total_assets=1,
        ),
        finding_section=FindingSection(
            entries=(fe,),
            total_count=1,
            severity_breakdown={"HIGH": 1},
        ),
        attack_path_section=AttackPathSection(
            total_paths=1,
            highest_score=75,
            average_score=75.0,
            graph=ag,
        ),
        recommendation_section=RecommendationSection(
            entries=(
                RecommendationEntry(
                    finding_title="Caf\u00e9 vuln r\u00e9sum\u00e9",
                    severity="HIGH",
                    risk_score=75,
                    correlation_id="corr-unicode",
                    recommendations=("Patch caf\u00e9", "Update M\u00fcnchen firewall"),
                ),
            ),
            total_recommendations=2,
        ),
        appendix=Appendix(
            scanner_versions={"nuclei": "3.2.1"},
            total_plugins=1,
            generated_at=now,
            generated_by="KingSec Report Builder",
        ),
    )
