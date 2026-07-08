"""Unit tests for HTML report templates."""

from __future__ import annotations

from kingsec.infrastructure.reporting import render_report_html
from tests.unit.infrastructure.reporting.conftest import build_report

_SECTIONS = (
    "Executive Summary",
    "Assessment Information",
    "Risk Summary",
    "Findings",
    "Conclusion",
)


class TestSections:
    def test_all_required_sections_present(self) -> None:
        html = render_report_html(build_report())
        for section in _SECTIONS:
            assert section in html
        # Assessment information rows.
        assert "Target" in html and "Scan Date" in html and "Assessment Status" in html
        assert "Completed" in html  # status constant (report ⇒ completed assessment)
        # Footer / branding.
        assert "<footer" in html and "confidential" in html.lower()

    def test_semantic_structure(self) -> None:
        html = render_report_html(build_report())
        assert html.startswith("<!DOCTYPE html>")
        for tag in ("<header", "<main", "<section", "<table", "<footer"):
            assert tag in html

    def test_branding_placeholder(self) -> None:
        html = render_report_html(build_report(), brand_name="AcmeSec")
        assert "AcmeSec" in html
        assert "logo-placeholder" in html


class TestSecurity:
    def test_html_is_escaped(self) -> None:
        html = render_report_html(build_report(title="<script>alert('x')</script>"))
        # Raw script from finding data must not appear; escaped form must.
        assert "<script>alert('x')</script>" not in html
        assert "&lt;script&gt;" in html

    def test_no_javascript_or_remote_resources(self) -> None:
        html = render_report_html(build_report())
        # The only <script> substring possible would be escaped finding text.
        assert "<script" not in html
        assert "http://" not in html and "https://" not in html
        assert "@import" not in html
        assert "url(" not in html
        assert "<iframe" not in html and "onerror=" not in html


class TestDeterminism:
    def test_identical_report_yields_identical_html(self) -> None:
        report = build_report()
        assert render_report_html(report) == render_report_html(report)

    def test_uses_report_generated_at_not_clock(self) -> None:
        # The fixed generated_at from the report must appear verbatim.
        html = render_report_html(build_report())
        assert "2026-07-07 12:00:00" in html


class TestEmptyFindings:
    def test_empty_findings_renders_gracefully(self) -> None:
        html = render_report_html(build_report(with_findings=False))
        assert "No findings were recorded" in html
        assert "no findings recorded" in html.lower()  # conclusion
