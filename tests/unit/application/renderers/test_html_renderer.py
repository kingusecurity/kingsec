"""HTML Report Renderer: comprehensive tests."""

from __future__ import annotations

from datetime import UTC, datetime
from pathlib import Path
from tempfile import NamedTemporaryFile

from tests.unit.application.renderers.test_markdown_renderer import (
    _empty_report,
    _minimal_report,
    _multi_report,
)

from kingsec.application.renderers.html_renderer import HTMLReportRenderer

_RENDERER = HTMLReportRenderer()


# ===========================================================================
# Basic rendering
# ===========================================================================


class TestBasicRendering:
    def test_returns_string(self) -> None:
        html_out = _RENDERER.render(_minimal_report())
        assert isinstance(html_out, str)

    def test_doctype(self) -> None:
        html_out = _RENDERER.render(_minimal_report())
        assert html_out.startswith("<!DOCTYPE html>")

    def test_html_tag(self) -> None:
        html_out = _RENDERER.render(_minimal_report())
        assert "<html" in html_out
        assert "</html>" in html_out

    def test_head_tag(self) -> None:
        html_out = _RENDERER.render(_minimal_report())
        assert "<head>" in html_out
        assert "</head>" in html_out

    def test_body_tag(self) -> None:
        html_out = _RENDERER.render(_minimal_report())
        assert "<body>" in html_out
        assert "</body>" in html_out

    def test_charset_meta(self) -> None:
        html_out = _RENDERER.render(_minimal_report())
        assert 'charset="utf-8"' in html_out

    def test_title_tag(self) -> None:
        html_out = _RENDERER.render(_minimal_report())
        assert "<title>" in html_out
        assert "KingSec Security Report" in html_out

    def test_container_div(self) -> None:
        html_out = _RENDERER.render(_minimal_report())
        assert 'class="container"' in html_out

    def test_generation_timestamp(self) -> None:
        html_out = _RENDERER.render(_minimal_report())
        assert "Generated:" in html_out
        assert "UTC" in html_out

    def test_utf8_encoding(self) -> None:
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
            summary_text="Café résumé avec 🛡️",
        )
        fe = FindingEntry(
            correlation_id="c-1",
            title="Café vuln",
            severity="HIGH",
            category="vuln",
            confidence=0.8,
            scanner_sources=("nuclei",),
            affected_assets=("München-01",),
            service=None,
            port=None,
            protocol=None,
            attack_surface=None,
            risk_score=75,
            risk_level="High",
            priority="High",
        )
        fs = FindingSection(entries=(fe,), total_count=1, severity_breakdown={"HIGH": 1})
        ts = TechnicalSummary(
            total_findings=1,
            total_correlations=1,
            total_enriched=1,
            total_risk_assessments=1,
            severity_breakdown={"HIGH": 1},
            category_breakdown={},
            scanner_coverage={},
        )
        rs = RiskSummary(
            score_distribution={"High": 1},
            average_score=75.0,
            highest_score=75,
            lowest_score=75,
            top_risk_factors=(),
        )
        ae = AssetEntry(asset="München-01", finding_count=1, highest_risk_score=75, average_risk_score=75.0)
        a_s = AssetSummary(entries=(ae,), total_assets=1)
        n1 = AttackNode(
            node_id="n-1",
            correlation_id="c-1",
            title="Café",
            severity="HIGH",
            category="vuln",
            attack_surface=None,
            service=None,
            port=None,
            protocol=None,
            asset="München-01",
            risk_score=75,
            risk_level="High",
        )
        p = AttackPath(
            path_id="p-1",
            nodes=(n1,),
            edges=(),
            attack_score=75,
            confidence=0.35,
            estimated_impact="High",
            attack_complexity="Simple",
            likelihood="Medium",
            reasoning=".",
            recommendations=(),
        )
        ag = AttackGraph(paths=(p,), total_paths=1, highest_score=75, average_score=75.0, metadata={})
        aps = AttackPathSection(total_paths=1, highest_score=75, average_score=75.0, graph=ag)
        re = RecommendationEntry(
            finding_title="Café", severity="HIGH", risk_score=75, correlation_id="c-1", recommendations=("Fix café",)
        )
        recs = RecommendationSection(entries=(re,), total_recommendations=1)
        app = Appendix(
            scanner_versions={"nuc🚀": "1"},
            total_plugins=1,
            generated_at=datetime(2026, 7, 17, tzinfo=UTC),
            generated_by="KingSec",
        )
        r = Report(
            report_id="rpt-u",
            title="UTF-8 Test",
            created_at=datetime(2026, 7, 17, tzinfo=UTC),
            executive_summary=es,
            technical_summary=ts,
            risk_summary=rs,
            asset_summary=a_s,
            finding_section=fs,
            attack_path_section=aps,
            recommendation_section=recs,
            appendix=app,
        )
        html_out = _RENDERER.render(r)
        assert "Café" in html_out
        assert "München" in html_out
        assert "nuc🚀" in html_out
        assert "🛡️" in html_out


# ===========================================================================
# Escaping
# ===========================================================================


class TestEscaping:
    def test_html_escaping_in_title(self) -> None:
        from kingsec.application.attack_path import (
            AttackGraph,
            AttackNode,
            AttackPath,
        )
        from kingsec.application.report import (
            Appendix,
            AssetSummary,
            AttackPathSection,
            ExecutiveSummary,
            FindingSection,
            RecommendationSection,
            Report,
            RiskSummary,
            TechnicalSummary,
        )

        es = ExecutiveSummary(
            total_findings=0,
            total_correlated=0,
            total_enriched=0,
            total_risk_assessments=0,
            critical_count=0,
            high_count=0,
            medium_count=0,
            low_count=0,
            informational_count=0,
            top_risk_score=0,
            average_risk_score=0.0,
            total_assets=0,
            summary_text="Safe <script>alert('xss')</script>",
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
        rs = RiskSummary(
            score_distribution={},
            average_score=0.0,
            highest_score=0,
            lowest_score=0,
            top_risk_factors=("<script>", "&escape"),
        )
        fs = FindingSection(entries=(), total_count=0, severity_breakdown={})
        n1 = AttackNode(
            node_id="n-1",
            correlation_id="c-1",
            title="<img>",
            severity="HIGH",
            category="vuln",
            attack_surface=None,
            service=None,
            port=None,
            protocol=None,
            asset="<test>",
            risk_score=0,
            risk_level="Low",
        )
        p = AttackPath(
            path_id="<path>",
            nodes=(n1,),
            edges=(),
            attack_score=0,
            confidence=0.0,
            estimated_impact="None",
            attack_complexity="Simple",
            likelihood="Low",
            reasoning=".",
            recommendations=("<malicious>",),
        )
        ag = AttackGraph(paths=(p,), total_paths=1, highest_score=0, average_score=0.0, metadata={})
        aps = AttackPathSection(total_paths=0, highest_score=0, average_score=0.0, graph=ag)
        recs = RecommendationSection(entries=(), total_recommendations=0)
        app = Appendix(
            scanner_versions={"<x>": "1"},
            total_plugins=1,
            generated_at=datetime(2026, 7, 17, tzinfo=UTC),
            generated_by="<script>",
        )
        r = Report(
            report_id="<rpt>",
            title="<escape test>",
            created_at=datetime(2026, 7, 17, tzinfo=UTC),
            executive_summary=es,
            technical_summary=ts,
            risk_summary=rs,
            asset_summary=AssetSummary(entries=(), total_assets=0),
            finding_section=fs,
            attack_path_section=aps,
            recommendation_section=recs,
            appendix=app,
        )
        html_out = _RENDERER.render(r)
        assert "&lt;escape test&gt;" in html_out
        assert "&amp;escape" in html_out
        assert "<script>" not in html_out
        assert "<img>" not in html_out
        assert "<test>" not in html_out
        assert "<path>" not in html_out
        assert "<x>" not in html_out
        assert "<rpt>" not in html_out


# ===========================================================================
# Deterministic output
# ===========================================================================


class TestDeterministic:
    def test_same_input_same_output(self) -> None:
        report = _minimal_report()
        h1 = _RENDERER.render(report)
        h2 = _RENDERER.render(report)
        assert h1 == h2


# ===========================================================================
# Empty report
# ===========================================================================


class TestEmptyReport:
    def test_render_empty(self) -> None:
        html_out = _RENDERER.render(_empty_report())
        assert "<h1>KingSec Security Report</h1>" in html_out

    def test_empty_no_findings_message(self) -> None:
        html_out = _RENDERER.render(_empty_report())
        assert "No findings to display" in html_out

    def test_empty_no_attack_paths_message(self) -> None:
        html_out = _RENDERER.render(_empty_report())
        assert "No attack paths identified" in html_out

    def test_empty_no_assets_message(self) -> None:
        html_out = _RENDERER.render(_empty_report())
        assert "No assets identified" in html_out

    def test_empty_no_recommendations_message(self) -> None:
        html_out = _RENDERER.render(_empty_report())
        assert "No recommendations available" in html_out


# ===========================================================================
# CSS presence
# ===========================================================================


class TestCSSPresence:
    def test_has_style_tag(self) -> None:
        html_out = _RENDERER.render(_minimal_report())
        assert "<style>" in html_out
        assert "</style>" in html_out

    def test_has_severity_colors(self) -> None:
        html_out = _RENDERER.render(_minimal_report())
        assert "severity-critical" in html_out
        assert "severity-high" in html_out
        assert "severity-medium" in html_out

    def test_has_badge_classes(self) -> None:
        html_out = _RENDERER.render(_minimal_report())
        assert "badge-critical" in html_out
        assert "badge-high" in html_out

    def test_has_table_styling(self) -> None:
        html_out = _RENDERER.render(_minimal_report())
        assert "border-collapse" in html_out

    def test_has_print_media_query(self) -> None:
        html_out = _RENDERER.render(_minimal_report())
        assert "@media print" in html_out

    def test_no_external_css(self) -> None:
        html_out = _RENDERER.render(_minimal_report())
        assert '<link rel="stylesheet"' not in html_out

    def test_no_javascript(self) -> None:
        html_out = _RENDERER.render(_minimal_report())
        assert "<script>" not in html_out
        assert "javascript:" not in html_out.lower()


# ===========================================================================
# Section ordering
# ===========================================================================


class TestSectionOrdering:
    def test_section_order(self) -> None:
        html_out = _RENDERER.render(_minimal_report())
        es_pos = html_out.index('id="executive-summary"')
        rs_pos = html_out.index('id="risk-summary"')
        tf_pos = html_out.index('id="technical-findings"')
        ap_pos = html_out.index('id="attack-paths"')
        as_pos = html_out.index('id="assets"')
        rec_pos = html_out.index('id="recommendations"')
        app_pos = html_out.index('id="appendix"')
        assert es_pos < rs_pos < tf_pos < ap_pos < as_pos < rec_pos < app_pos


# ===========================================================================
# Multiple findings
# ===========================================================================


class TestMultipleFindings:
    def test_all_findings_present(self) -> None:
        html_out = _RENDERER.render(_multi_report())
        assert "RCE in Apache" in html_out
        assert "XSS in Web App" in html_out
        assert "Weak Ciphers" in html_out

    def test_finding_severity_badges(self) -> None:
        html_out = _RENDERER.render(_multi_report())
        assert "badge-critical" in html_out
        assert "badge-high" in html_out
        assert "badge-medium" in html_out


# ===========================================================================
# Multiple attack paths
# ===========================================================================


class TestMultipleAttackPaths:
    def test_attack_path_nodes_table(self) -> None:
        html_out = _RENDERER.render(_minimal_report())
        assert "<th>Title</th>" in html_out
        assert "<th>Severity</th>" in html_out

    def test_attack_path_reasoning(self) -> None:
        html_out = _RENDERER.render(_minimal_report())
        assert "Attack chain detected" in html_out


# ===========================================================================
# Assets
# ===========================================================================


class TestAssets:
    def test_asset_table_present(self) -> None:
        html_out = _RENDERER.render(_minimal_report())
        assert "<th>Asset</th>" in html_out

    def test_multiple_assets(self) -> None:
        html_out = _RENDERER.render(_multi_report())
        assert "10.0.0.1" in html_out
        assert "10.0.0.2" in html_out
        assert "10.0.0.3" in html_out


# ===========================================================================
# Recommendations
# ===========================================================================


class TestRecommendations:
    def test_recommendation_actions(self) -> None:
        html_out = _RENDERER.render(_minimal_report())
        assert "Update OpenSSH" in html_out
        assert "Disable root login" in html_out


# ===========================================================================
# File writing
# ===========================================================================


class TestFileWriting:
    def test_write_creates_file(self) -> None:
        report = _minimal_report()
        with NamedTemporaryFile(mode="w", suffix=".html", delete=False, encoding="utf-8") as f:
            path = Path(f.name)
        try:
            _RENDERER.write(report, path)
            assert path.exists()
            content = path.read_text(encoding="utf-8")
            assert "<!DOCTYPE html>" in content
            assert "<h1>KingSec Security Report</h1>" in content
        finally:
            path.unlink(missing_ok=True)

    def test_write_utf8_encoding(self) -> None:
        report = _minimal_report()
        with NamedTemporaryFile(mode="w", suffix=".html", delete=False, encoding="utf-8") as f:
            path = Path(f.name)
        try:
            _RENDERER.write(report, path)
            content = path.read_text(encoding="utf-8")
            assert 'charset="utf-8"' in content
        finally:
            path.unlink(missing_ok=True)


# ===========================================================================
# Idempotency
# ===========================================================================


class TestIdempotency:
    def test_render_twice_identical(self) -> None:
        report = _minimal_report()
        h1 = _RENDERER.render(report)
        h2 = _RENDERER.render(report)
        assert h1 == h2

    def test_write_twice_identical_content(self) -> None:
        report = _minimal_report()
        with NamedTemporaryFile(mode="w", suffix=".html", delete=False, encoding="utf-8") as f1:
            p1 = Path(f1.name)
        with NamedTemporaryFile(mode="w", suffix=".html", delete=False, encoding="utf-8") as f2:
            p2 = Path(f2.name)
        try:
            _RENDERER.write(report, p1)
            _RENDERER.write(report, p2)
            assert p1.read_text(encoding="utf-8") == p2.read_text(encoding="utf-8")
        finally:
            p1.unlink(missing_ok=True)
            p2.unlink(missing_ok=True)
