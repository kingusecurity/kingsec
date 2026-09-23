"""Unit tests for HTML report templates."""

from __future__ import annotations

import dataclasses

import pytest

from kingsec.domain import ScannerRunState, ScannerRunSummary, Severity, SeverityDemotionReason
from kingsec.infrastructure.reporting import render_report_html
from kingsec.infrastructure.scanner.nmap import NON_URL_DEFAULT_PORT_SPECIFICATION
from tests.unit.infrastructure.reporting.conftest import build_report

_SECTIONS = (
    "Executive Summary",
    "Scope at a Glance",
    "Assessment Information",
    "Scanner Coverage",
    "Risk Summary",
    "Findings",
    "Finding Details",
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
    """Task 4 FIX 2: this is a customer deliverable - whether the assessor
    has an AI provider configured is internal plumbing, never something
    the customer's own report should disclose. Previously, a report with
    no Critical/High findings AND no AI configured rendered BOTH "no
    business-impact analysis is required" AND "AI-generated... are not
    available for this report" together - directly contradictory (the
    second sentence implies analysis WAS needed and just isn't
    available). Fixed: no top-level AI-availability callout at all,
    ever; a report needing no analysis says only that.
    """

    def test_no_critical_or_high_findings_says_only_that_no_ai_mention(self) -> None:
        """The exact regression this fix closes: no Critical/High
        findings (analysis genuinely not required) must render ONLY that
        sentence - no AI/provider/configuration language alongside it,
        contradictory or otherwise."""
        from kingsec.domain import Severity

        report = build_report()
        low_entries = tuple(dataclasses.replace(e, severity=Severity.LOW) for e in report.entries)
        report = dataclasses.replace(report, entries=low_entries)  # ai_enabled stays False
        html = render_report_html(report)
        assert "No Critical or High severity findings" in html
        assert "AI" not in html
        assert "provider" not in html.lower()

    def test_no_ai_explanation_omits_the_business_impact_section_entirely(self) -> None:
        """Phase 2C Step 2, FIX 3: real report evidence showed a Critical
        finding's card rendering "No business-impact explanation is
        available for this finding" - a section whose content is only its
        own absence. Fixed: no AI provider configured (build_report()'s
        default fixture has a CRITICAL finding but no explanation) must
        omit the Business Impact section entirely, and reference neither
        AI, a provider, nor an unavailable explanation anywhere."""
        html = render_report_html(build_report())  # ai_enabled=False by default
        assert "AI" not in html
        assert "provider" not in html.lower()
        assert '<section id="business-impact">' not in html
        assert "No business-impact explanation is available" not in html

    def test_ai_enabled_renders_explanation_text(self) -> None:
        report = build_report()
        enriched_entries = tuple(
            dataclasses.replace(e, ai_explanation=f"Business risk: {e.title} could expose customer data.")
            for e in report.entries
        )
        report = dataclasses.replace(report, entries=enriched_entries, ai_enabled=True)
        html = render_report_html(report)
        assert "could expose customer data" in html
        assert "No business-impact explanation is available" not in html

    def test_ai_enabled_but_call_failed_omits_the_section_no_ai_mention(self) -> None:
        """A failed AI call (ai_enabled=True but every explanation stays
        None) must behave identically to no provider configured at all -
        FIX 3 omits the section by the finding's actual explanation
        content, not by whether a provider was configured."""
        report = dataclasses.replace(build_report(), ai_enabled=True)  # entries keep ai_explanation=None
        html = render_report_html(report)
        assert '<section id="business-impact">' not in html
        assert "AI" not in html
        assert "provider" not in html.lower()

    def test_some_findings_explained_others_not_only_explained_ones_render(self) -> None:
        """Mixed case: when SOME Critical/High findings have a real
        explanation and others don't, the ones without one render
        nothing - not mentioned in this section at all - rather than an
        empty-stub card."""
        report = build_report()
        critical = next(e for e in report.entries if e.severity is Severity.CRITICAL)
        explained = dataclasses.replace(
            critical, title="Explained Critical", ai_explanation="Business risk: could expose customer data."
        )
        unexplained = dataclasses.replace(critical, title="Unexplained Critical", ai_explanation=None)
        report = dataclasses.replace(report, entries=(explained, unexplained), ai_enabled=True)
        html = render_report_html(report)
        start = html.find('<section id="business-impact">')
        end = html.find("</section>", start) + len("</section>")
        business_impact_html = html[start:end]
        assert "Explained Critical" in business_impact_html
        assert "Unexplained Critical" not in business_impact_html

    def test_no_critical_or_high_findings_skips_analysis(self) -> None:
        report = build_report(title="Missing headers")
        # Rewrite the critical finding down to LOW so nothing qualifies.
        from kingsec.domain import Severity

        low_entries = tuple(dataclasses.replace(e, severity=Severity.LOW) for e in report.entries)
        report = dataclasses.replace(report, entries=low_entries)
        html = render_report_html(report)
        assert "No Critical or High severity findings" in html


class TestFindingDetails:
    """Phase 6 Task 2: Technical Findings and Remediation Steps were merged
    into one section (Finding Details) - a finding's evidence and its fix
    now live in the same card instead of two separately-paginated ones. All
    the individual content assertions below are unchanged from before the
    merge (same underlying functions, same text); what changed is that they
    now all come from a single `id="finding-details"` section instead of
    two.
    """

    def test_renders_recommendation_text(self) -> None:
        html = render_report_html(build_report())
        assert "Fix" in html and "use params" in html  # from the fixture's Recommendation

    def test_no_longer_renders_a_fabricated_effort_estimate(self) -> None:
        # Phase 2C Step 2, FIX 2: a severity-based "estimated fix effort"
        # (e.g. "Large" for a Critical finding, regardless of how trivial
        # the actual fix is) was removed rather than replaced with a
        # differently-shaped guess - no real effort-tracking data exists
        # anywhere upstream to ground an estimate in.
        html = render_report_html(build_report())
        assert "Estimated fix effort" not in html
        assert "estimated fix effort" not in html

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

    def test_renders_description_and_evidence(self) -> None:
        html = render_report_html(build_report())
        assert "injectable parameter" in html  # finding description
        assert "matched-at" in html  # evidence summary
        assert "Not available" in html  # honest CVE/CVSS gap

    def test_finding_without_evidence_gets_honest_note(self) -> None:
        html = render_report_html(build_report())
        assert "No evidence was recorded for this finding" in html

    def test_evidence_and_remediation_for_the_same_finding_share_one_card(self) -> None:
        """The actual point of the Task 2 merge: a finding's evidence and
        its remediation must be readable without leaving its card - assert
        both appear inside the SAME finding-card div, not merely somewhere
        on the page."""
        report = build_report()
        critical = next(e for e in report.entries if e.severity is Severity.CRITICAL)
        html = render_report_html(report)
        card_start = html.index(f'id="finding-{critical.finding_id}"')
        card_end = html.index("</div>", html.index("<h4>Remediation</h4>", card_start))
        card_html = html[card_start:card_end]
        assert "<h4>Evidence</h4>" in card_html
        assert "<h4>Remediation</h4>" in card_html

    def test_old_separate_sections_no_longer_exist(self) -> None:
        """Regression guard: the two old, separately-rendered sections must
        both be gone, not merely renamed - their removal is the actual
        page-count reduction Task 2 exists to produce."""
        html = render_report_html(build_report())
        assert 'id="technical-findings"' not in html
        assert 'id="remediation-steps"' not in html
        assert "<h2>Technical Findings</h2>" not in html
        assert "<h2>Remediation Steps</h2>" not in html


class TestFindingAnchorLinks:
    """Phase 6 Task 2: Risk Prioritization and the Findings table are now
    compact indices that link to each finding's full card in Finding
    Details, instead of each independently re-rendering the finding."""

    def test_every_finding_has_a_stable_anchor_id(self) -> None:
        report = build_report()
        html = render_report_html(report)
        for entry in report.entries:
            assert f'id="finding-{entry.finding_id}"' in html

    def test_risk_prioritization_links_to_the_real_anchor(self) -> None:
        report = build_report()
        html = render_report_html(report)
        section = html.split('id="risk-prioritization"')[1].split("</section>")[0]
        for entry in report.entries:
            assert f'href="#finding-{entry.finding_id}"' in section

    def test_findings_table_links_to_the_real_anchor(self) -> None:
        report = build_report()
        html = render_report_html(report)
        section = html.split('<section id="findings">')[1].split("</section>")[0]
        for entry in report.entries:
            assert f'href="#finding-{entry.finding_id}"' in section

    def test_every_link_target_actually_exists_in_the_document(self) -> None:
        """The real safety net: every #finding-<id> href in the whole
        document must resolve to a real id="finding-<id>" somewhere in the
        same document - a broken internal link is worse than none."""
        import re

        report = build_report()
        html = render_report_html(report)
        hrefs = set(re.findall(r'href="#(finding-[^"]+)"', html))
        ids = set(re.findall(r'id="(finding-[^"]+)"', html))
        assert hrefs, "expected at least one finding anchor link"
        assert hrefs <= ids


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


class TestAuthenticationScopeDisclosure:
    """Phase 2C Step 2, Addition 1: every rendered report - not only
    zero-finding ones - must disclose that this was an unauthenticated
    external assessment, since a clean or low-finding result says
    nothing about what sits behind a login."""

    def test_zero_finding_report_contains_the_disclosure(self) -> None:
        html = render_report_html(build_report(with_findings=False))
        section = html.split('id="limitations"')[1].split("</section>")[0]
        assert "unauthenticated external assessment" in section
        assert "reachable only after authentication was not tested" in section

    def test_findings_rich_report_contains_the_disclosure(self) -> None:
        html = render_report_html(build_report())  # default fixture has CRITICAL + LOW
        section = html.split('id="limitations"')[1].split("</section>")[0]
        assert "unauthenticated external assessment" in section

    def test_completed_with_gaps_report_contains_the_disclosure(self) -> None:
        from kingsec.domain.enums import AssessmentStatus

        report = dataclasses.replace(build_report(), assessment_status=AssessmentStatus.COMPLETED_WITH_GAPS)
        html = render_report_html(report)
        section = html.split('id="limitations"')[1].split("</section>")[0]
        assert "unauthenticated external assessment" in section

    @pytest.mark.parametrize(
        "report",
        [
            build_report(with_findings=False),
            build_report(),
            build_report(title="<script>alert(1)</script>"),
            dataclasses.replace(build_report(), ai_enabled=True),
            dataclasses.replace(
                build_report(),
                scanner_summary=(
                    ScannerRunSummary(scanner_id="nmap", name="Nmap", status=ScannerRunState.SUCCEEDED, findings_count=1),
                ),
            ),
            dataclasses.replace(build_report(), score_version="v1"),
        ],
        ids=[
            "zero-findings",
            "default-findings",
            "html-in-title",
            "ai-enabled",
            "with-scanner-summary",
            "v1-scored",
        ],
    )
    def test_sentence_present_across_report_variants(self, report) -> None:
        """The seat named in _AUTHENTICATION_SCOPE_SENTENCE's own comment
        (templates.py) is only real if no reachable report shape can
        render without it - this asserts that across a representative
        matrix, not just the three named cases above."""
        html = render_report_html(report)
        section = html.split('id="limitations"')[1].split("</section>")[0]
        assert "unauthenticated external assessment" in section


class TestUrgentActionFraming:
    """Phase 2C Step 2, Addition 2: a Critical (or High) finding must force
    an unconditional act-now callout, above and independent of the
    computed score/band - the band label alone must never be the only
    carrier of that message.

    report.count_for() (used by _urgent_action_note) reads the report's
    own precomputed severity_counts field, not a live count of .entries -
    so these tests rebuild severity_counts to match whatever .entries they
    construct, exactly as Report.from_assessment() itself does.
    """

    @staticmethod
    def _with_entries(report, entries):
        from collections import Counter

        counts = Counter(e.severity for e in entries)
        severity_counts = tuple(sorted(counts.items(), key=lambda kv: kv[0], reverse=True))
        return dataclasses.replace(report, entries=entries, severity_counts=severity_counts)

    def test_critical_plus_informational_gets_immediate_action_framing_regardless_of_band(self) -> None:
        # 1 Critical blended with 25 Informational findings - Phase 2C Step
        # 1's exact scenario: this must NOT read as merely "Fair"/"Good".
        report = build_report()
        critical = next(e for e in report.entries if e.severity is Severity.CRITICAL)
        info_entries = tuple(
            dataclasses.replace(critical, title=f"Info {i}", severity=Severity.INFORMATIONAL) for i in range(25)
        )
        report = self._with_entries(report, (critical, *info_entries))
        html = render_report_html(report)

        assert "Critical finding(s) present" in html
        assert "immediate remediation required" in html
        # Independent of / above the score panel, not inside the band label.
        assert html.index("Critical finding(s) present") < html.index("Overall Risk Score")

    def test_no_critical_or_high_omits_the_callout(self) -> None:
        report = build_report()
        low_entries = tuple(dataclasses.replace(e, severity=Severity.LOW) for e in report.entries)
        report = self._with_entries(report, low_entries)
        html = render_report_html(report)
        assert "Critical finding(s) present" not in html
        assert "High-severity finding(s) present" not in html

    def test_high_without_critical_gets_its_own_framing(self) -> None:
        report = build_report()
        high_entries = tuple(dataclasses.replace(e, severity=Severity.HIGH) for e in report.entries)
        report = self._with_entries(report, high_entries)
        html = render_report_html(report)
        assert "High-severity finding(s) present" in html
        assert "prompt remediation recommended" in html
        assert "Critical finding(s) present" not in html

    def test_critical_and_high_both_present_stack_independently(self) -> None:
        report = build_report()
        entries = list(report.entries)
        entries.append(dataclasses.replace(entries[0], title="Extra High", severity=Severity.HIGH))
        report = self._with_entries(report, tuple(entries))
        html = render_report_html(report)
        assert "Critical finding(s) present" in html
        assert "High-severity finding(s) present" in html

    def test_generic_action_required_callout_is_suppressed_when_urgent_framing_fires(self) -> None:
        """Phase 2C Step 2, FIX 4: real report evidence showed the urgent
        Critical framing immediately followed by the weaker generic
        "Action required. Remediation is recommended..." callout, two
        lines apart - the second dilutes the first. build_report()'s
        default fixture has a Critical finding, so urgent framing fires
        and the generic callout must not appear at all."""
        html = render_report_html(build_report())
        assert "Critical finding(s) present" in html
        assert "Action required." not in html
        assert "Remediation is recommended for the issues identified below" not in html

    def test_generic_action_required_callout_still_renders_for_low_only_reports(self) -> None:
        """FIX 4 must not suppress the generic callout unconditionally -
        only when the urgent Critical/High framing actually fired. A
        Low-only report (which still sets verdict.action_required) must
        keep showing it, since there is no urgent framing to reinforce."""
        report = build_report()
        low_entries = tuple(dataclasses.replace(e, severity=Severity.LOW) for e in report.entries)
        report = self._with_entries(report, low_entries)
        html = render_report_html(report)
        assert "Critical finding(s) present" not in html
        assert "High-severity finding(s) present" not in html
        assert "Action required." in html
        assert "Remediation is recommended for the issues identified below" in html


class TestNoSignalBandOverride:
    """Phase 2C Step 2, (d) (approved threshold): zero findings above
    Informational severity always scores 100.0 under both formulas and
    would otherwise band as "Strong" - that label implies deep, hard-won
    assurance a merely quiet unauthenticated scan hasn't earned. Extends
    Phase 2A's partial-coverage override point with a distinct label,
    since "Partial Coverage" would misstate what happened here (every
    scanner completed)."""

    @staticmethod
    def _with_entries(report, entries):
        from collections import Counter

        counts = Counter(e.severity for e in entries)
        severity_counts = tuple(sorted(counts.items(), key=lambda kv: kv[0], reverse=True))
        return dataclasses.replace(report, entries=entries, severity_counts=severity_counts)

    def test_zero_findings_total_gets_the_override(self) -> None:
        html = render_report_html(build_report(with_findings=False))
        assert "No Findings — Coverage Limited" in html
        assert ">Strong</span>" not in html

    def test_informational_only_findings_get_the_override(self) -> None:
        report = build_report()
        info_entries = tuple(dataclasses.replace(e, severity=Severity.INFORMATIONAL) for e in report.entries)
        report = self._with_entries(report, info_entries)
        html = render_report_html(report)
        assert "No Findings — Coverage Limited" in html
        assert ">Strong</span>" not in html

    def test_a_low_finding_does_not_trigger_the_override(self) -> None:
        """Original Task-6 Run 4/5's exact shape (real Low findings from
        genuine nmap port enumeration) must still read Strong - the
        override is for near-zero SIGNAL, not merely a high raw score."""
        report = build_report()
        low_entries = tuple(dataclasses.replace(e, severity=Severity.LOW) for e in report.entries)
        report = self._with_entries(report, low_entries)
        html = render_report_html(report)
        assert "No Findings — Coverage Limited" not in html
        assert ">Strong</span>" in html

    def test_completed_with_gaps_zero_findings_keeps_partial_coverage_label(self) -> None:
        """The pre-existing Phase 2A override takes priority: a report
        that is BOTH zero-signal AND incomplete must show the honest
        "coverage was incomplete" label, not the unrelated no-signal one -
        the two must never fight over the same band slot."""
        from kingsec.domain.enums import AssessmentStatus

        report = dataclasses.replace(
            build_report(with_findings=False), assessment_status=AssessmentStatus.COMPLETED_WITH_GAPS
        )
        html = render_report_html(report)
        assert "Partial Coverage" in html
        assert "No Findings — Coverage Limited" not in html

    def test_override_applies_to_v1_scored_reports_too(self) -> None:
        # v1's penalty for Informational is 0 and for zero findings is 0,
        # so this condition scores 100.0 under v1 as well - the override
        # is about the SIGNAL, not about which formula scored it.
        report = dataclasses.replace(build_report(with_findings=False), score_version="v1")
        html = render_report_html(report)
        assert "No Findings — Coverage Limited" in html
        assert ">Strong</span>" not in html


class TestScoreLineScannerDenominator:
    """Phase 2C Step 2, FIX 4: real report evidence (GAP-1) showed (d)'s
    no-signal override rendering "100.0 / 100" with NO scanner denominator
    at all - identical in form to a genuinely clean, fully-covered result,
    even though the underlying assessment had zero scanner coverage. Zero
    findings from zero coverage and zero findings from full coverage are
    completely different claims; the denominator must appear on every
    score line, regardless of which band override fires."""

    def test_no_signal_report_with_real_coverage_shows_the_denominator(self) -> None:
        """The case (d) was actually built for: scanners that DID run
        successfully and found nothing above Informational - the score
        line must still say so explicitly, not just show a bare number."""
        summary = (
            ScannerRunSummary(scanner_id="nmap", name="Nmap", status=ScannerRunState.SUCCEEDED, findings_count=0),
            ScannerRunSummary(scanner_id="nuclei", name="Nuclei", status=ScannerRunState.SUCCEEDED, findings_count=0),
        )
        report = build_report(with_findings=False, scanner_summary=summary)
        html = render_report_html(report)
        assert "No Findings — Coverage Limited" in html
        assert "Based on 2 of 2 scanner(s)." in html

    def test_normal_strong_band_report_also_shows_the_denominator(self) -> None:
        """Not just the no-signal override case - ANY score line with real
        scanner_summary data must show the denominator."""
        summary = (
            ScannerRunSummary(scanner_id="nmap", name="Nmap", status=ScannerRunState.SUCCEEDED, findings_count=6),
        )
        report = build_report(with_findings=False, scanner_summary=summary)
        low_entries = tuple(
            dataclasses.replace(e, severity=Severity.LOW) for e in (build_report().entries[:1])
        )
        report = dataclasses.replace(
            report,
            entries=low_entries,
            severity_counts=((Severity.LOW, 1),),
        )
        html = render_report_html(report)
        assert ">Strong</span>" in html
        assert "Based on 1 of 1 scanner(s)." in html

    def test_v1_score_line_also_shows_the_denominator(self) -> None:
        summary = (
            ScannerRunSummary(scanner_id="nmap", name="Nmap", status=ScannerRunState.SUCCEEDED, findings_count=0),
        )
        report = dataclasses.replace(
            build_report(with_findings=False, scanner_summary=summary), score_version="v1"
        )
        html = render_report_html(report)
        assert "Based on 1 of 1 scanner(s)." in html

    def test_no_scanner_summary_at_all_omits_the_denominator_not_a_bogus_zero_of_zero(self) -> None:
        # A pre-feature fixture with no scanner_summary has nothing to
        # report - "0 of 0 scanner(s)" would be noise, not honesty.
        html = render_report_html(build_report(with_findings=False))
        assert "Based on" not in html

    def test_incomplete_coverage_still_uses_its_own_inline_denominator(self) -> None:
        """The Partial Coverage branch already states its own denominator
        inline ("based on N of M scanners") - this must not gain a second,
        duplicate coverage_clause on top of it."""
        from kingsec.domain.enums import AssessmentStatus

        summary = (
            ScannerRunSummary(scanner_id="nmap", name="Nmap", status=ScannerRunState.SUCCEEDED, findings_count=1),
            ScannerRunSummary(scanner_id="nuclei", name="Nuclei", status=ScannerRunState.FAILED),
        )
        report = dataclasses.replace(
            build_report(scanner_summary=summary), assessment_status=AssessmentStatus.COMPLETED_WITH_GAPS
        )
        html = render_report_html(report)
        # Scoped to the score-panel specifically: the verdict headline
        # above it (Verdict.from_findings()'s own coverage-lead sentence,
        # pre-existing and unrelated to this fix) legitimately also
        # mentions "1 of 2 scanners ran" - only the score line's OWN
        # denominator must not be duplicated.
        score_panel = html.split('class="score-panel"')[1].split("</div></div>")[0]
        assert score_panel.count("of 2 scanner") == 1


class TestZeroFindingsActionCalloutIsHonest:
    """Phase 2C Step 2, GAP-1 fix round FIX 5a: real report evidence showed
    "Action required. Remediation is recommended for the issues identified
    below." rendered with ZERO findings - a COMPLETED_WITH_GAPS assessment
    where the coverage gap itself, not any specific finding, is why action
    is required (Verdict.from_findings() forces action_required=True here
    regardless of findings). The empty-content defect family again."""

    def test_zero_findings_incomplete_coverage_does_not_claim_issues_below(self) -> None:
        from kingsec.domain.enums import AssessmentStatus

        summary = (
            ScannerRunSummary(scanner_id="nmap", name="Nmap", status=ScannerRunState.SUCCEEDED, findings_count=0),
            ScannerRunSummary(scanner_id="nuclei", name="Nuclei", status=ScannerRunState.FAILED),
        )
        report = dataclasses.replace(
            build_report(with_findings=False, scanner_summary=summary),
            assessment_status=AssessmentStatus.COMPLETED_WITH_GAPS,
        )
        html = render_report_html(report)
        assert "Action required." in html
        assert "Remediation is recommended for the issues identified below" not in html
        assert "Scanner coverage was incomplete for this assessment" in html

    def test_findings_present_still_says_issues_identified_below(self) -> None:
        """Unaffected control: when there ARE real findings driving action
        (not a coverage gap), the original phrasing stays exactly as
        before. Severity forced to LOW (not Critical/High) so the urgent-
        action framing doesn't suppress this callout entirely."""
        report = build_report()
        low_entries = tuple(dataclasses.replace(e, severity=Severity.LOW) for e in report.entries)
        report = dataclasses.replace(
            report, entries=low_entries, severity_counts=((Severity.LOW, len(low_entries)),)
        )
        html = render_report_html(report)
        assert "Remediation is recommended for the issues identified below" in html


class TestStrongBandNarrativeActionAware:
    """Phase 2C Step 2, GAP-1 fix round FIX 5b: same contradiction class
    Phase 2A-b fixed for "generally sound standing" appearing next to
    "Action required" (docs/STATUS.md) - GAP-3's real evidence showed
    "This places the assessed environment in strong standing overall."
    sitting three lines above "Action required" for a fully-COMPLETED
    assessment with 6 real Low findings. Resolved on the narrative side,
    matching Phase 2A-b's own precedent (not by suppressing the callout,
    which carries a true "these findings still need fixing" signal)."""

    def test_strong_band_with_real_findings_names_the_remediation_need(self) -> None:
        """GAP-3's exact real shape: a fully-COMPLETED assessment scoring
        >=90 (Strong) from real Low findings that genuinely warrant
        remediation."""
        report = build_report()
        low_entries = tuple(dataclasses.replace(e, severity=Severity.LOW) for e in report.entries)
        report = dataclasses.replace(
            report, entries=low_entries, severity_counts=((Severity.LOW, len(low_entries)),)
        )
        html = render_report_html(report)
        section = html.split('class="score-panel"')[1].split("</div></div>")[0]
        assert ">Strong</span>" in section
        assert "though the findings below still warrant remediation" in section
        assert "Action required." in html

    def test_score_narrative_unit_action_required_true(self) -> None:
        from kingsec.infrastructure.reporting.templates import _score_narrative

        text = _score_narrative(95.0, action_required=True)
        assert "though the findings below still warrant remediation" in text

    def test_score_narrative_unit_action_required_false_unchanged(self) -> None:
        from kingsec.infrastructure.reporting.templates import _score_narrative

        text = _score_narrative(95.0, action_required=False)
        assert text == "This places the assessed environment in strong standing overall."

    def test_lower_tiers_unaffected_by_action_required_param(self) -> None:
        """Only the Strong tier (>=90) needed this - Good/Fair/Weak/Critical
        already name "issues that warrant attention" unconditionally, so
        they never contradicted an Action Required callout to begin with."""
        from kingsec.infrastructure.reporting.templates import _score_narrative

        assert _score_narrative(80.0, action_required=True) == _score_narrative(80.0, action_required=False)


class TestScopeAtAGlance:
    """Phase 6 Task 1: a compact preview of the scope-limiting disclosures
    (authentication scope, port coverage, scanner coverage), placed right
    after the Executive Summary so a reader who stops after page 2 still
    knows what was not examined. An addition, not a replacement - the full
    versions of all three must still render, unchanged, in Limitations &
    Methodology Notes."""

    def test_section_present_and_positioned_after_executive_summary(self) -> None:
        html = render_report_html(build_report())
        assert 'id="scope-at-a-glance"' in html
        assert html.index('id="executive-summary"') < html.index('id="scope-at-a-glance"')

    def test_contains_the_authentication_scope_short_sentence(self) -> None:
        html = render_report_html(build_report())
        section = html.split('id="scope-at-a-glance"')[1].split("</section>")[0]
        assert "unauthenticated assessment" in section

    def test_full_authentication_sentence_still_renders_unchanged_in_limitations(self) -> None:
        """Every disclosure must survive - the compact preview is an
        addition, never a substitute for the full version."""
        html = render_report_html(build_report())
        limitations = html.split('id="limitations"')[1].split("</section>")[0]
        assert "unauthenticated external assessment" in limitations
        assert "reachable only after authentication was not tested" in limitations

    def test_contains_port_coverage_when_nmap_recorded_a_spec(self) -> None:
        summary = (
            ScannerRunSummary(
                scanner_id="nmap",
                name="Nmap",
                status=ScannerRunState.SUCCEEDED,
                findings_count=1,
                port_specification="top 1000 ports",
            ),
        )
        html = render_report_html(build_report(scanner_summary=summary))
        section = html.split('id="scope-at-a-glance"')[1].split("</section>")[0]
        assert "Port coverage: top 1000 ports." in section

    def test_omits_port_coverage_line_when_nmap_did_not_run(self) -> None:
        html = render_report_html(build_report(scanner_summary=()))
        section = html.split('id="scope-at-a-glance"')[1].split("</section>")[0]
        assert "Port coverage" not in section

    def test_contains_scanner_coverage_summary(self) -> None:
        summary = (
            ScannerRunSummary(scanner_id="nmap", name="Nmap", status=ScannerRunState.SUCCEEDED, findings_count=1),
            ScannerRunSummary(scanner_id="nuclei", name="Nuclei", status=ScannerRunState.FAILED),
        )
        html = render_report_html(build_report(scanner_summary=summary))
        section = html.split('id="scope-at-a-glance"')[1].split("</section>")[0]
        assert "Scanner coverage: 1 of 2 scanner(s) completed" in section


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
        """Task 4 FIX 1: a genuine non-URL run now RECORDS the explicit
        sentinel (never None - None means "not recorded" now, a
        different fact). The Limitations section must disclose real
        coverage and attribute the default to nmap, never imply KingSec
        selected the ports (Task 4, point 3)."""
        html = render_report_html(
            build_report(scanner_summary=(self._nmap_summary(port_specification=NON_URL_DEFAULT_PORT_SPECIFICATION),))
        )
        assert "own default port selection" in html
        assert "not every possible port" in html

    def test_failed_nmap_gets_no_default_port_claim(self) -> None:
        """A FAILED nmap must not be silently read as "used the default" -
        port_specification is None here too, but for a different reason
        (nmap never completed), and the two must not be conflated."""
        # A companion SUCCEEDED scanner keeps this a real COMPLETED_WITH_GAPS
        # shape (Phase 2C Step 2 GAP-1 fix: a report can never be built at
        # all when EVERY scanner failed) - the assertion is about nmap
        # specifically, not about the assessment's overall coverage.
        other = ScannerRunSummary(scanner_id="nuclei", name="Nuclei", status=ScannerRunState.SUCCEEDED, findings_count=1)
        html = render_report_html(
            build_report(
                scanner_summary=(
                    self._nmap_summary(port_specification=None, status=ScannerRunState.FAILED),
                    other,
                )
            )
        )
        assert "Nmap's port scan" not in html

    def test_absent_key_disclosure_says_not_recorded(self) -> None:
        """port_specification=None (a genuinely absent key - a row
        persisted before this field existed) must disclose as unknown,
        never assert nmap's default was used when the record doesn't
        say so (Task 4 FIX 1)."""
        html = render_report_html(build_report(scanner_summary=(self._nmap_summary(port_specification=None),)))
        assert "was not recorded" in html
        assert "unknown" in html
        assert "own default port selection" not in html

    def test_absent_key_and_explicit_non_url_sentinel_render_different_disclosures(self) -> None:
        """THE required test for FIX 1: a summary with an ABSENT key
        (port_specification=None, e.g. a pre-Task-2 row) and a summary
        with the explicit non-URL sentinel (a genuine current non-URL
        run) must render DIFFERENT disclosures. If they render the same,
        the fix has not landed - that collapse is exactly the "nothing
        found vs nothing looked" defect this fix exists to close."""
        html_absent = render_report_html(build_report(scanner_summary=(self._nmap_summary(port_specification=None),)))
        html_explicit = render_report_html(
            build_report(scanner_summary=(self._nmap_summary(port_specification=NON_URL_DEFAULT_PORT_SPECIFICATION),))
        )

        assert html_absent != html_explicit
        assert "was not recorded" in html_absent
        assert "was not recorded" not in html_explicit
        assert "own default port selection" in html_explicit
        assert "own default port selection" not in html_absent


class TestRateLimitDisclosure:
    """Phase 2B-c Priority 3: request-rate limiting applied by ffuf/gobuster
    must be disclosed in the Limitations section, same standard as port
    coverage above - derived from the recorded value, never hardcoded."""

    def _run(
        self,
        scanner_id: str,
        name: str,
        *,
        rate_limit_description: str | None,
        status: ScannerRunState = ScannerRunState.SUCCEEDED,
    ) -> ScannerRunSummary:
        return ScannerRunSummary(
            scanner_id=scanner_id,
            name=name,
            status=status,
            findings_count=1,
            rate_limit_description=rate_limit_description,
        )

    def test_no_disclosure_when_no_scanner_recorded_a_rate_limit(self) -> None:
        html = render_report_html(build_report())
        section = html.split('id="limitations"')[1].split("</section>")[0]
        assert "Request-rate limiting" not in section

    def test_disclosure_states_the_recorded_ffuf_rate(self) -> None:
        summary = (self._run("ffuf", "ffuf Scanner", rate_limit_description="40 requests/second (ffuf -rate)"),)
        html = render_report_html(build_report(scanner_summary=summary))
        section = html.split('id="limitations"')[1].split("</section>")[0]
        assert "ffuf Scanner" in section
        assert "40 requests/second" in section

    def test_disclosure_lists_multiple_scanners(self) -> None:
        summary = (
            self._run("ffuf", "ffuf Scanner", rate_limit_description="40 requests/second (ffuf -rate)"),
            self._run(
                "gobuster",
                "Gobuster Scanner",
                rate_limit_description="100ms delay per request (gobuster --delay)",
            ),
        )
        html = render_report_html(build_report(scanner_summary=summary))
        section = html.split('id="limitations"')[1].split("</section>")[0]
        assert "ffuf Scanner" in section
        assert "Gobuster Scanner" in section

    def test_failed_scanner_gets_no_rate_limit_claim(self) -> None:
        # A companion SUCCEEDED scanner keeps this a real COMPLETED_WITH_GAPS
        # shape (Phase 2C Step 2 GAP-1 fix: a report can never be built at
        # all when EVERY scanner failed) - the assertion is about ffuf
        # specifically, not about the assessment's overall coverage.
        summary = (
            self._run("nmap", "Nmap", rate_limit_description=None),
            self._run(
                "ffuf",
                "ffuf Scanner",
                rate_limit_description="40 requests/second (ffuf -rate)",
                status=ScannerRunState.FAILED,
            ),
        )
        html = render_report_html(build_report(scanner_summary=summary))
        section = html.split('id="limitations"')[1].split("</section>")[0]
        assert "Request-rate limiting" not in section

    def test_disclosure_changes_with_the_recorded_value(self) -> None:
        """THE required linkage test, same standard as port coverage's own
        (test_disclosure_changes_with_the_recorded_specification above)."""
        summary_a = (self._run("ffuf", "ffuf Scanner", rate_limit_description="40 requests/second (ffuf -rate)"),)
        summary_b = (
            self._run("ffuf", "ffuf Scanner", rate_limit_description="disabled (rate_limit_per_second=0)"),
        )
        html_a = render_report_html(build_report(scanner_summary=summary_a))
        html_b = render_report_html(build_report(scanner_summary=summary_b))
        assert "40 requests/second" in html_a
        assert "40 requests/second" not in html_b
        assert "disabled" in html_b


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


class TestRiskOverTimeVersionDisclosure:
    """Phase 2C Step 2, Addition B: a trend chart must never plot v1 and
    v2 points as if directly comparable - a history point scored under a
    different formula than the current report is excluded from the
    plotted series and its exclusion disclosed, never silently blended
    into one undifferentiated line."""

    def test_mixed_version_history_excludes_prior_version_points(self) -> None:
        from kingsec.domain.report import HistoryPoint

        report = build_report()  # score_version defaults to "v2"
        prior_v1 = HistoryPoint(generated_at=report.generated_at, executive_score=12.3, score_version="v1")
        prior_v2 = HistoryPoint(generated_at=report.generated_at, executive_score=77.7, score_version="v2")
        report = dataclasses.replace(report, history=(prior_v1, prior_v2))

        html = render_report_html(report)
        chart_section = html.split('aria-label="Risk score over time chart"')[1].split("</svg>")[0]

        # The v1 point's score must not appear as a plotted value...
        assert ">12</text>" not in chart_section
        # ...while the same-version point still does.
        assert ">78</text>" in chart_section
        # And the exclusion must be disclosed, not silently dropped.
        assert "1 earlier report(s)" in html
        assert "different formula version" in html

    def test_all_same_version_history_has_no_exclusion_note(self) -> None:
        from kingsec.domain.report import HistoryPoint

        report = build_report()
        prior = HistoryPoint(generated_at=report.generated_at, executive_score=50.0, score_version="v2")
        report = dataclasses.replace(report, history=(prior,))
        html = render_report_html(report)
        assert "different formula version" not in html

    def test_only_mixed_version_history_falls_back_to_insufficient_history(self) -> None:
        """If EVERY prior point is a different formula version than the
        current report, none are comparable - this must read as
        insufficient (same-formula) history, honestly, not silently show
        a single-point chart or crash."""
        from kingsec.domain.report import HistoryPoint

        report = build_report()
        prior_v1 = HistoryPoint(generated_at=report.generated_at, executive_score=12.3, score_version="v1")
        report = dataclasses.replace(report, history=(prior_v1,))
        html = render_report_html(report)
        assert "Insufficient history" in html
        assert "different formula version" in html


class TestRiskPrioritization:
    def test_lists_findings_worst_first(self) -> None:
        html = render_report_html(build_report())
        # The fixture's CRITICAL finding must appear before the LOW one in the list.
        section = html.split('id="risk-prioritization"')[1].split("</section>")[0]
        assert section.index("SQL Injection") < section.index("Missing headers")

    def test_no_longer_renders_a_fabricated_effort_estimate(self) -> None:
        html = render_report_html(build_report())
        section = html.split('id="risk-prioritization"')[1].split("</section>")[0]
        assert "estimated fix effort" not in section.lower()


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
            # A companion SUCCEEDED scanner keeps this a real
            # COMPLETED_WITH_GAPS shape (Phase 2C Step 2 GAP-1 fix: a report
            # can never be built at all when EVERY scanner failed).
            ScannerRunSummary(scanner_id="nmap", name="Nmap", status=ScannerRunState.SUCCEEDED, findings_count=1),
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


class TestScannerCoverageStderrDisclosure:
    """Phase 2B-c Priority 4 (recurring-class instance nine): a failed
    scanner's real stderr must render in the coverage block, distinct
    from the generic safe skipped_reason it accompanies."""

    def test_stderr_excerpt_appended_when_present(self) -> None:
        from kingsec.domain import ScannerRunSummary
        from kingsec.domain.enums import ScannerRunState

        summary = (
            # A companion SUCCEEDED scanner keeps this a real
            # COMPLETED_WITH_GAPS shape (Phase 2C Step 2 GAP-1 fix: a report
            # can never be built at all when EVERY scanner failed).
            ScannerRunSummary(scanner_id="nmap", name="Nmap", status=ScannerRunState.SUCCEEDED, findings_count=1),
            ScannerRunSummary(
                scanner_id="ffuf",
                name="ffuf",
                status=ScannerRunState.FAILED,
                skipped_reason="The scan process exited with an error before producing usable results.",
                stderr_excerpt="ffuf: cannot resolve host",
            ),
        )
        html = render_report_html(build_report(scanner_summary=summary))
        section = html.split('id="scanner-coverage"')[1].split("</section>")[0]
        assert "stderr: ffuf: cannot resolve host" in section

    def test_no_stderr_excerpt_omits_the_stderr_fragment(self) -> None:
        from kingsec.domain import ScannerRunSummary
        from kingsec.domain.enums import ScannerRunState

        summary = (
            ScannerRunSummary(scanner_id="nmap", name="Nmap", status=ScannerRunState.SUCCEEDED, findings_count=1),
            ScannerRunSummary(
                scanner_id="trivy",
                name="Trivy",
                status=ScannerRunState.FAILED,
                skipped_reason="binary not found",
            ),
        )
        html = render_report_html(build_report(scanner_summary=summary))
        section = html.split('id="scanner-coverage"')[1].split("</section>")[0]
        assert "stderr:" not in section

    def test_different_stderr_prevents_two_failures_from_merging_into_one_sentence(self) -> None:
        """Two scanners sharing the same skipped_reason but different real
        stderr must NOT be grouped as if they failed identically - the
        whole point of this feature is telling them apart."""
        from kingsec.domain import ScannerRunSummary
        from kingsec.domain.enums import ScannerRunState

        summary = (
            # A companion SUCCEEDED scanner keeps this a real
            # COMPLETED_WITH_GAPS shape (Phase 2C Step 2 GAP-1 fix: a report
            # can never be built at all when EVERY scanner failed).
            ScannerRunSummary(scanner_id="nmap", name="Nmap", status=ScannerRunState.SUCCEEDED, findings_count=1),
            ScannerRunSummary(
                scanner_id="ffuf",
                name="ffuf",
                status=ScannerRunState.FAILED,
                skipped_reason="The scan process exited with an error before producing usable results.",
                stderr_excerpt="ffuf: cannot resolve host",
            ),
            ScannerRunSummary(
                scanner_id="gobuster",
                name="Gobuster",
                status=ScannerRunState.FAILED,
                skipped_reason="The scan process exited with an error before producing usable results.",
                stderr_excerpt="gobuster: wordlist file not found",
            ),
        )
        html = render_report_html(build_report(scanner_summary=summary))
        section = html.split('id="scanner-coverage"')[1].split("</section>")[0]
        assert "ffuf: cannot resolve host" in section
        assert "gobuster: wordlist file not found" in section
        assert "ffuf, Gobuster" not in section

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


class TestSeverityDemotionDisclosure:
    """Phase 2B-c Priority 1b: the Limitations section must disclose when
    KingSec's own classifier reduced a finding's severity below what its
    path name alone would suggest - the same "don't silently change the
    answer" standard as the port-coverage disclosure above."""

    def _demote(self, report, index: int, *, original: Severity, reason: SeverityDemotionReason):
        entries = list(report.entries)
        entries[index] = dataclasses.replace(entries[index], original_severity=original, demotion_reason=reason)
        return dataclasses.replace(report, entries=tuple(entries))

    def test_no_disclosure_when_nothing_was_demoted(self) -> None:
        html = render_report_html(build_report())
        section = html.split('id="limitations"')[1].split("</section>")[0]
        assert "severity scoring reduced" not in section

    def test_disclosure_states_count_and_content_type_reason(self) -> None:
        report = self._demote(
            build_report(), 0, original=Severity.HIGH, reason=SeverityDemotionReason.CONTENT_TYPE_MISMATCH
        )
        html = render_report_html(report)
        section = html.split('id="limitations"')[1].split("</section>")[0]
        assert "reduced 1 finding" in section
        assert "HTML page instead of the expected file type" in section
        assert "response shape as most of this scan" not in section

    def test_disclosure_states_baseline_shape_reason(self) -> None:
        report = self._demote(
            build_report(), 0, original=Severity.HIGH, reason=SeverityDemotionReason.BASELINE_SHAPE_MATCH
        )
        html = render_report_html(report)
        section = html.split('id="limitations"')[1].split("</section>")[0]
        assert "response shape as most of this scan" in section
        assert "HTML page instead of the expected file type" not in section

    def test_disclosure_counts_both_reasons_when_both_occur(self) -> None:
        report = self._demote(
            build_report(), 0, original=Severity.HIGH, reason=SeverityDemotionReason.CONTENT_TYPE_MISMATCH
        )
        report = self._demote(report, 1, original=Severity.MEDIUM, reason=SeverityDemotionReason.BASELINE_SHAPE_MATCH)
        html = render_report_html(report)
        section = html.split('id="limitations"')[1].split("</section>")[0]
        assert "reduced 2 findings" in section
        assert "HTML page instead of the expected file type" in section
        assert "response shape as most of this scan" in section

    def test_demoted_findings_remain_listed_with_evidence(self) -> None:
        # The disclosure must never imply the finding was removed.
        report = self._demote(
            build_report(), 0, original=Severity.HIGH, reason=SeverityDemotionReason.CONTENT_TYPE_MISMATCH
        )
        html = render_report_html(report)
        assert report.entries[0].title in html
        section = html.split('id="limitations"')[1].split("</section>")[0]
        assert "still listed above with their evidence intact" in section
