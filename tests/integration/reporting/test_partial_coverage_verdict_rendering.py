"""Phase 10: real report-generation-path reproduction + regression for
partial-scan verdict honesty.

Phase 09 proved the PDF is where an operator actually reads the verdict
(§5 Scenario 4). This file drives Report.from_assessment() and
render_report_html() together - the same two calls generate_report.py's
own use case makes - rather than asserting on Verdict in isolation, so the
fix is proven where it is actually read, not just at the DTO level.

Written FIRST, before any fix, per Phase 10 ground rule #2.
"""

from __future__ import annotations

import html as html_module

from kingsec.domain import (
    Assessment,
    Authorization,
    Report,
    ScannerRunSummary,
    Severity,
    Target,
    TargetType,
)
from kingsec.domain.enums import ScannerRunState
from kingsec.infrastructure.reporting.templates import render_report_html

# Old (pre-Phase-2A) string vocabulary -> ScannerRunState.
_STATUS_MAP = {
    "completed": ScannerRunState.SUCCEEDED,
    "failed": ScannerRunState.FAILED,
    "skipped": ScannerRunState.SKIPPED_INCOMPATIBLE,
    "pending": ScannerRunState.PENDING,
}


def _finding(severity: Severity, title: str):
    from kingsec.domain import Finding

    return Finding.create(title, "Detail.", severity)


def _build_report(findings: tuple, scanner_summary: tuple) -> Report:
    assessment = Assessment.create(Target("10.0.0.5", TargetType.IP_ADDRESS))
    assessment.authorize(Authorization.grant("tester", scope="10.0.0.5"))
    assessment.start()
    for f in findings:
        assessment.record_finding(f)
    assessment.record_scanner_summary(scanner_summary)
    assessment.complete()
    return Report.from_assessment(assessment)


def _summary(scanner_id: str, name: str, status: str, findings_count: int = 0) -> ScannerRunSummary:
    return ScannerRunSummary(scanner_id=scanner_id, name=name, status=_STATUS_MAP[status], findings_count=findings_count)


class TestScenario3RenderedReportNoLongerReadsAsClean:
    """The exact live defect from Phase 09 §5 Scenario 3, rendered through
    the real HTML report template - not just asserted at the domain
    Verdict level."""

    def test_verdict_section_no_longer_says_no_action_required(self) -> None:
        findings = tuple(_finding(Severity.INFORMATIONAL, f"Finding {i}") for i in range(7))
        summary = (
            _summary("nuclei", "Nuclei Scanner", "completed", findings_count=7),
            _summary("nikto", "Nikto Scanner", "failed"),
            _summary("ffuf", "ffuf Scanner", "failed"),
            _summary("gobuster", "Gobuster Scanner", "failed"),
            _summary("zap", "OWASP ZAP", "failed"),
        )
        report = _build_report(findings, summary)
        rendered = html_module.unescape(render_report_html(report))

        assert "no action required" not in rendered.lower()
        assert "did not complete" in rendered
        # The named scanners appear in the qualified verdict text, not just
        # the separate, already-existing Scanner Coverage section.
        verdict_section = rendered.split('id="conclusion"')[0]
        assert "Nikto Scanner" in verdict_section or "did not complete" in verdict_section

    def test_conclusion_section_does_not_falsely_imply_clean_when_zero_findings(self) -> None:
        """The most dangerous case, rendered: zero findings recorded at all,
        most scanners failed. templates.py's _conclusion() has its own,
        independent zero-findings branch that bypasses verdict.action_required
        entirely - confirm it does not silently say 'no findings recorded'
        with no mention of incomplete coverage."""
        summary = (
            _summary("nuclei", "Nuclei Scanner", "completed"),
            _summary("nmap", "Nmap Scanner", "failed"),
            _summary("nikto", "Nikto Scanner", "failed"),
        )
        report = _build_report((), summary)
        rendered = html_module.unescape(render_report_html(report))
        conclusion_section = rendered.split('id="conclusion"')[1].split("</section>")[0]

        assert "did not complete" in conclusion_section or "incomplete" in conclusion_section.lower()

    def test_fully_completed_clean_report_still_reads_as_clean(self) -> None:
        """The signal must be specific: a genuinely clean, fully-executed
        scan must still render unqualified."""
        summary = (_summary("nuclei", "Nuclei Scanner", "completed"), _summary("nmap", "Nmap Scanner", "completed"))
        report = _build_report((), summary)
        rendered = html_module.unescape(render_report_html(report))
        conclusion_section = rendered.split('id="conclusion"')[1].split("</section>")[0]

        assert "did not complete" not in rendered
        assert "no findings recorded" in conclusion_section.lower() or "completed" in conclusion_section.lower()
