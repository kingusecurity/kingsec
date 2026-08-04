"""Unit tests for HTML report templates."""

from __future__ import annotations

import dataclasses

from kingsec.infrastructure.reporting import render_report_html
from tests.unit.infrastructure.reporting.conftest import build_report

_SECTIONS = (
    "Executive Summary",
    "Assessment Information",
    "Risk Summary",
    "Findings",
    "Technical Findings",
    "Remediation Steps",
    "Visual Elements",
    "Risk Prioritization",
    "Affected Assets Summary",
    "Limitations",
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

    def test_executive_summary_includes_score(self) -> None:
        report = build_report()
        html = render_report_html(report)
        assert "Overall Risk Score" in html
        assert f"{report.executive_score:.1f} / 100" in html

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
        # Evidence text may legitimately mention a URL (e.g. "matched-at
        # http://..."), so this checks for no ACTIVE remote-resource loading
        # (a real <script>/<img>/@import/url() fetch), not literal "http://"
        # substrings — inert, escaped evidence text is expected and safe.
        html = render_report_html(build_report())
        assert "<script" not in html
        assert "@import" not in html
        assert "url(" not in html
        assert "<iframe" not in html and "onerror=" not in html
        assert '<img src="http' not in html and "<img src='http" not in html


class TestDeterminism:
    def test_identical_report_yields_identical_html(self) -> None:
        report = build_report()
        assert render_report_html(report) == render_report_html(report)

    def test_uses_report_generated_at_not_clock(self) -> None:
        # The fixed generated_at from the report must appear verbatim.
        html = render_report_html(build_report())
        assert "2026-07-07 12:00:00" in html


class TestBusinessImpact:
    def test_ai_status_note_shows_even_with_no_critical_or_high_findings(self) -> None:
        # Regression test: a real assessment with only Low/Informational
        # findings (e.g. plain open-port scans) and no AI provider configured
        # previously rendered NOTHING about AI at all — the "no critical/high
        # findings" early return skipped the AI-status note entirely.
        from kingsec.domain import Severity

        report = build_report()
        low_entries = tuple(dataclasses.replace(e, severity=Severity.LOW) for e in report.entries)
        report = dataclasses.replace(report, entries=low_entries)  # ai_enabled stays False
        html = render_report_html(report)
        assert "No Critical or High severity findings" in html
        assert "are not available for this report" in html

    def test_no_ai_configured_shows_honest_note(self) -> None:
        # build_report()'s critical finding has no ai_explanation and
        # ai_enabled defaults to False.
        html = render_report_html(build_report())
        assert "are not available for this report" in html

    def test_ai_enabled_renders_explanation_text(self) -> None:
        report = build_report()
        enriched_entries = tuple(
            dataclasses.replace(e, ai_explanation=f"Business risk: {e.title} could expose customer data.")
            for e in report.entries
        )
        report = dataclasses.replace(report, entries=enriched_entries, ai_enabled=True)
        html = render_report_html(report)
        assert "could expose customer data" in html
        assert "are not available for this report" not in html

    def test_ai_enabled_but_call_failed_shows_per_finding_note(self) -> None:
        report = dataclasses.replace(build_report(), ai_enabled=True)  # entries keep ai_explanation=None
        html = render_report_html(report)
        assert "did not return a business-impact explanation" in html

    def test_no_critical_or_high_findings_skips_analysis(self) -> None:
        report = build_report(title="Missing headers")
        # Rewrite the critical finding down to LOW so nothing qualifies.
        from kingsec.domain import Severity

        low_entries = tuple(dataclasses.replace(e, severity=Severity.LOW) for e in report.entries)
        report = dataclasses.replace(report, entries=low_entries)
        html = render_report_html(report)
        assert "No Critical or High severity findings" in html


class TestRemediationSteps:
    def test_renders_recommendation_text_and_effort(self) -> None:
        html = render_report_html(build_report())
        assert "Fix" in html and "use params" in html  # from the fixture's Recommendation
        assert "Estimated fix effort" in html
        assert "Large" in html  # the fixture's CRITICAL finding

    def test_finding_without_recommendation_gets_honest_note(self) -> None:
        # The fixture's second finding ("Missing headers", LOW) has no recommendation,
        # and isn't a known finding type — no generic guidance exists for it either.
        html = render_report_html(build_report())
        assert "No specific remediation guidance is available" in html

    def test_open_port_finding_gets_generic_guidance_not_the_honest_note(self) -> None:
        # Regression test: open-port findings (what nmap actually produces)
        # previously always showed "No specific remediation guidance is
        # available" since they never have an AI-generated recommendation in
        # this environment — real, curated generic guidance should show instead.
        report = build_report()
        renamed = tuple(
            dataclasses.replace(e, title="Open port 445/tcp", recommendations=()) for e in report.entries
        )
        report = dataclasses.replace(report, entries=renamed)
        html = render_report_html(report)
        assert "Review whether this open port/service is required" in html
        assert "No specific remediation guidance is available" not in html


class TestTechnicalFindings:
    def test_renders_description_and_evidence(self) -> None:
        html = render_report_html(build_report())
        assert "injectable parameter" in html  # finding description
        assert "matched-at" in html  # evidence summary
        assert "Not available" in html  # honest CVE/CVSS gap

    def test_finding_without_evidence_gets_honest_note(self) -> None:
        html = render_report_html(build_report())
        assert "No evidence was recorded for this finding" in html


class TestCoverPage:
    def test_renders_metadata(self) -> None:
        report = build_report()
        html = render_report_html(report)
        assert 'class="cover-page"' in html
        assert report.target in html
        assert report.scope in html
        assert report.authorized_by in html
        assert report.assessment_id in html

    def test_page_numbers_configured(self) -> None:
        html = render_report_html(build_report())
        assert "counter(page)" in html and "counter(pages)" in html
        # The cover page itself suppresses the footer via :first.
        assert "@page :first" in html


class TestLimitations:
    def test_present_and_honest_about_cve_gap(self) -> None:
        html = render_report_html(build_report())
        assert "Limitations" in html
        assert "does not correlate findings to specific CVE identifiers" in html
        assert "false negatives" in html and "false positives" in html


class TestVisualElements:
    def test_severity_distribution_renders_svg_bars(self) -> None:
        html = render_report_html(build_report())
        assert "Visual Elements" in html
        assert "Severity Distribution" in html
        assert "<svg" in html
        assert "<rect" in html  # the fixture has CRITICAL + LOW findings

    def test_no_findings_skips_severity_chart_gracefully(self) -> None:
        html = render_report_html(build_report(with_findings=False))
        assert "No findings to chart" in html

    def test_insufficient_history_shows_honest_note(self) -> None:
        # build_report() never sets .history, so this is the target's first report.
        html = render_report_html(build_report())
        assert "Insufficient history" in html

    def test_two_or_more_points_render_a_trend_line(self) -> None:
        from kingsec.domain.report import HistoryPoint

        report = build_report()
        prior = HistoryPoint(generated_at=report.generated_at, executive_score=50.0)
        report = dataclasses.replace(report, history=(prior,))
        html = render_report_html(report)
        assert "<polyline" in html
        assert "Insufficient history" not in html

    def test_trend_chart_shows_value_labels_and_axis(self) -> None:
        # Regression test: the chart previously showed two connected dots with
        # no visible score values or axis, so it wasn't informative on its own.
        from kingsec.domain.report import HistoryPoint

        report = build_report()
        prior = HistoryPoint(generated_at=report.generated_at, executive_score=50.0)
        report = dataclasses.replace(report, history=(prior,))
        html = render_report_html(report)
        chart_section = html.split('aria-label="Risk score over time chart"')[1]
        # Both the prior point's score (50) and the current report's score
        # must be visible as text somewhere in the chart's SVG.
        assert ">50</text>" in chart_section
        assert f">{report.executive_score:.0f}</text>" in chart_section
        # A y-axis with at least the 0/50/100 gridline labels is present.
        assert ">0</text>" in chart_section
        assert ">100</text>" in chart_section


class TestRiskPrioritization:
    def test_lists_findings_worst_first_with_effort(self) -> None:
        html = render_report_html(build_report())
        # The fixture's CRITICAL finding must appear before the LOW one in the list.
        section = html.split('id="risk-prioritization"')[1].split("</section>")[0]
        assert section.index("SQL Injection") < section.index("Missing headers")
        assert "estimated fix effort: Large" in section


class TestAffectedAssets:
    def test_renders_target_and_finding_count(self) -> None:
        report = build_report()
        html = render_report_html(report)
        assert "Affected Assets Summary" in html
        assert report.target in html
        assert f"<td>{report.total_findings}</td>" in html


class TestEmptyFindings:
    def test_empty_findings_renders_gracefully(self) -> None:
        html = render_report_html(build_report(with_findings=False))
        assert "No findings were recorded" in html
        assert "no findings recorded" in html.lower()  # conclusion
