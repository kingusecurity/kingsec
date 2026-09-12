"""Unit tests for HTML report templates."""

from __future__ import annotations

import dataclasses

from kingsec.domain import ScannerRunState, ScannerRunSummary
from kingsec.infrastructure.reporting import render_report_html
from tests.unit.infrastructure.reporting.conftest import build_report

_SECTIONS = (
    "Executive Summary",
    "Assessment Information",
    "Scanner Coverage",
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

    def test_when_cve_data_present_blanket_disclaimer_is_not_used(self) -> None:
        """Regression test: a report with real CVE/CVSS data on at least one
        finding (Nuclei/Trivy) must not claim, in Limitations, that it
        "does not correlate findings to specific CVE identifiers" - that
        was true when no scanner correlated to CVE data, and is simply
        false once one does."""
        report = build_report()
        entries = report.entries
        cve_entry = dataclasses.replace(
            entries[0], cve_ids=("CVE-2026-53666",), cvss_score=6.1, cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N"
        )
        report = dataclasses.replace(report, entries=(cve_entry, *entries[1:]))

        html = render_report_html(report)

        assert "does not correlate findings to specific CVE identifiers" not in html
        assert "CVE-2026-53666" in html
        assert "6.1 (CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N)" in html


class TestPortCoverageDisclosure:
    """Task 4: the Limitations section must state real nmap port coverage,
    derived from ScannerRunSummary.port_specification - never a fixed
    sentence that could go stale relative to what the scanner actually
    recorded. The required test is test_disclosure_changes_with_the_recorded_specification
    below: it asserts the LINKAGE (different spec -> different rendered
    text), not just that some particular wording appears once.
    """

    def _nmap_summary(self, *, port_specification: str | None, status: ScannerRunState = ScannerRunState.SUCCEEDED) -> ScannerRunSummary:
        return ScannerRunSummary(
            scanner_id="nmap",
            name="Nmap",
            status=status,
            findings_count=1,
            port_specification=port_specification,
        )

    def test_no_disclosure_when_nmap_did_not_run(self) -> None:
        html = render_report_html(build_report(scanner_summary=()))
        assert "Nmap's port scan" not in html

    def test_url_target_specification_appears_verbatim(self) -> None:
        spec = "nmap default port sweep + explicit port 18080"
        html = render_report_html(build_report(scanner_summary=(self._nmap_summary(port_specification=spec),)))
        assert spec in html
        assert "not every possible port" in html

    def test_disclosure_changes_with_the_recorded_specification(self) -> None:
        """THE required linkage test (Task 4, point 4): a test that only
        asserted fixed wording would pass even if _port_coverage_note()
        silently stopped reading port_specification at all. Assert the
        actual linkage instead - two different recorded specifications
        must produce two different rendered disclosures, each containing
        its OWN specification text and not the other's."""
        spec_a = "nmap default port sweep + explicit port 18080"
        spec_b = "nmap default port sweep + explicit port 9443"

        html_a = render_report_html(build_report(scanner_summary=(self._nmap_summary(port_specification=spec_a),)))
        html_b = render_report_html(build_report(scanner_summary=(self._nmap_summary(port_specification=spec_b),)))

        assert spec_a in html_a
        assert spec_b not in html_a
        assert spec_b in html_b
        assert spec_a not in html_b

    def test_non_url_target_states_nmaps_own_default_not_a_kingsec_choice(self) -> None:
        """port_specification is None for a non-URL target (nmap's plain
        default, nothing explicit to disclose) - the Limitations section
        must still disclose real coverage, and must attribute the default
        to nmap, never imply KingSec selected the ports (Task 4, point 3)."""
        html = render_report_html(build_report(scanner_summary=(self._nmap_summary(port_specification=None),)))
        assert "nmap's own default port selection" in html
        assert "uncommon port" in html

    def test_failed_nmap_gets_no_default_port_claim(self) -> None:
        """A FAILED nmap must not be silently read as "used the default" -
        port_specification is None here too, but for a different reason
        (nmap never completed), and the two must not be conflated."""
        html = render_report_html(
            build_report(scanner_summary=(self._nmap_summary(port_specification=None, status=ScannerRunState.FAILED),))
        )
        assert "Nmap's port scan" not in html


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

    def test_first_point_label_does_not_collide_with_axis_gridline_labels(self) -> None:
        # Regression test: the first history point always sits at the exact
        # x-position of the y-axis gridline labels (0/25/50/75/100), so any
        # purely vertical (above/below) offset for its value label eventually
        # collides with SOME gridline label — a first attempt at fixing a
        # collision with "100" just relocated it onto "75" instead, at a
        # different score. The real fix separates them horizontally.
        import re

        from kingsec.domain.report import HistoryPoint

        report = build_report()  # own score comes from its CRITICAL+LOW fixture
        report = dataclasses.replace(
            report,
            history=(HistoryPoint(generated_at=report.generated_at, executive_score=100.0),),
        )
        html = render_report_html(report)
        chart_section = html.split('aria-label="Risk score over time chart"')[1].split("</svg>")[0]

        # The first point's label uses text-anchor="start" (placed to the
        # right of its dot); the axis labels use text-anchor="end" (right-
        # aligned against the left edge). Their x-positions must be clearly
        # separated, not just their y-positions.
        first_point_label = re.search(r'x="([\d.]+)"[^>]*text-anchor="start"[^>]*fill="#0b3d63">100</text>', chart_section)
        axis_100_label = re.search(r'x="([\d.]+)"[^>]*text-anchor="end"[^>]*fill="#777">100</text>', chart_section)
        assert first_point_label is not None, "expected the first point's '100' label to use text-anchor=start"
        assert axis_100_label is not None
        assert float(first_point_label.group(1)) > float(axis_100_label.group(1)) + 5


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


class TestScannerCoverage:
    def test_no_scanner_summary_renders_honest_fallback(self) -> None:
        html = render_report_html(build_report())
        section = html.split('id="scanner-coverage"')[1].split("</section>")[0]
        assert "No scanner outcome was recorded" in section

    def test_profile_gated_outcome_groups_by_status_and_reason(self) -> None:
        from kingsec.domain import ScannerRunSummary
        from kingsec.domain.enums import ScannerRunState

        summary = (
            ScannerRunSummary(scanner_id="nmap", name="Nmap", status=ScannerRunState.SUCCEEDED, findings_count=7),
            ScannerRunSummary(
                scanner_id="nuclei",
                name="Nuclei",
                status=ScannerRunState.SKIPPED_INCOMPATIBLE,
                skipped_reason="excluded by profile",
            ),
            ScannerRunSummary(
                scanner_id="nikto",
                name="Nikto",
                status=ScannerRunState.SKIPPED_INCOMPATIBLE,
                skipped_reason="excluded by profile",
            ),
            ScannerRunSummary(
                scanner_id="trivy", name="Trivy", status=ScannerRunState.FAILED, skipped_reason="binary not found"
            ),
            ScannerRunSummary(
                scanner_id="semgrep", name="Semgrep", status=ScannerRunState.FAILED, skipped_reason="binary not found"
            ),
        )
        html = render_report_html(build_report(scanner_summary=summary))
        section = html.split('id="scanner-coverage"')[1].split("</section>")[0]

        assert "Nmap: completed, 7 findings." in section
        assert "Nuclei, Nikto: not run (excluded by profile)." in section
        assert "Trivy, Semgrep: not run (binary not found)." in section

    def test_internal_error_framing_is_stripped(self) -> None:
        """A raw exception message from the scanner orchestrator (error code
        tag + 'unexpected error in plugin' wrapper) must never leak into a
        customer-facing report verbatim."""
        from kingsec.domain import ScannerRunSummary
        from kingsec.domain.enums import ScannerRunState

        summary = (
            ScannerRunSummary(
                scanner_id="trivy",
                name="Trivy",
                status=ScannerRunState.FAILED,
                skipped_reason="unexpected error in plugin 'trivy': [KS-SCAN-001] scan timed out after 600s",
            ),
        )
        html = render_report_html(build_report(scanner_summary=summary))
        section = html.split('id="scanner-coverage"')[1].split("</section>")[0]

        assert "Trivy: not run (scan timed out after 600s)." in section
        assert "KS-SCAN-001" not in section
        assert "unexpected error in plugin" not in section

    def test_singular_finding_count_has_no_trailing_s(self) -> None:
        from kingsec.domain import ScannerRunSummary
        from kingsec.domain.enums import ScannerRunState

        summary = (
            ScannerRunSummary(scanner_id="nmap", name="Nmap", status=ScannerRunState.SUCCEEDED, findings_count=1),
        )
        html = render_report_html(build_report(scanner_summary=summary))
        section = html.split('id="scanner-coverage"')[1].split("</section>")[0]
        assert "Nmap: completed, 1 finding." in section

    def test_succeeded_scanner_warning_is_rendered(self) -> None:
        """Phase 2B Task 2: a scanner that succeeded but not quite as
        configured (e.g. nmap's URL-derived port overriding an operator's
        own -p) must say so in the report, not only in a log line - the
        report is the user surface, the log is not."""
        from kingsec.domain import ScannerRunSummary
        from kingsec.domain.enums import ScannerRunState

        summary = (
            ScannerRunSummary(
                scanner_id="nmap",
                name="Nmap",
                status=ScannerRunState.SUCCEEDED,
                findings_count=9,
                warnings=("Operator-configured port selection (-p 9999) was overridden by the URL's own port.",),
            ),
        )
        html = render_report_html(build_report(scanner_summary=summary))
        section = html.split('id="scanner-coverage"')[1].split("</section>")[0]
        assert "Nmap: completed, 9 findings" in section
        assert "Operator-configured port selection" in section
        assert "was overridden by the URL" in section

    def test_no_warning_produces_unchanged_sentence(self) -> None:
        """A scanner with no warnings renders exactly as before this task -
        no stray separator or empty warning clause."""
        from kingsec.domain import ScannerRunSummary
        from kingsec.domain.enums import ScannerRunState

        summary = (
            ScannerRunSummary(scanner_id="nmap", name="Nmap", status=ScannerRunState.SUCCEEDED, findings_count=9),
        )
        html = render_report_html(build_report(scanner_summary=summary))
        section = html.split('id="scanner-coverage"')[1].split("</section>")[0]
        assert "Nmap: completed, 9 findings." in section
        assert "—" not in section

    def test_scanner_names_are_escaped(self) -> None:
        from kingsec.domain import ScannerRunSummary
        from kingsec.domain.enums import ScannerRunState

        summary = (
            ScannerRunSummary(
                scanner_id="x",
                name="<script>alert('x')</script>",
                status=ScannerRunState.SUCCEEDED,
                findings_count=0,
            ),
        )
        html = render_report_html(build_report(scanner_summary=summary))
        assert "<script>alert('x')</script>" not in html
        assert "&lt;script&gt;" in html
