"""HTML template generation for assessment reports.

Pure and dependency-free (only the standard library): given a domain ``Report``
snapshot, produce a complete, self-contained HTML document. This module never
imports a rendering library, so it is trivially unit-testable everywhere.

Security properties:
    * Every dynamic value is passed through ``html.escape`` — no raw HTML can be
      injected from finding data.
    * Styling is a single embedded ``<style>`` block. There is NO JavaScript, NO
      remote resource (no external CSS/fonts/images), and NO ``url()`` fetches.
    * Deterministic: all content derives from the immutable ``Report`` (including
      its ``generated_at``); nothing is read from the clock at render time, and
      the domain already orders entries worst-first.
"""

from __future__ import annotations

import re
from html import escape

from kingsec.domain import HistoryPoint, Report, Severity
from kingsec.domain.report import FindingSummary

# Reports are only ever generated from a COMPLETED assessment (domain-enforced),
# so the status shown is a safe constant rather than guesswork.
_ASSESSMENT_STATUS = "Completed"

_SEVERITY_ORDER = (
    Severity.CRITICAL,
    Severity.HIGH,
    Severity.MEDIUM,
    Severity.LOW,
    Severity.INFORMATIONAL,
)

# Minimal, self-contained stylesheet. System font stack only (no web fonts).
_STYLESHEET = """
@page {
    size: A4; margin: 2cm;
    @bottom-center { content: "Page " counter(page) " of " counter(pages); font-size: 9px; color: #777; }
}
@page :first {
    @bottom-center { content: none; }
}
* { box-sizing: border-box; }
.cover-page { break-after: page; display: flex; flex-direction: column;
     justify-content: center; height: 22cm; }
.cover-page h1 { font-size: 32px; color: #0b3d63; margin: 0 0 8px; }
.cover-page .subtitle { font-size: 14px; margin-bottom: 32px; }
.cover-page table { width: auto; }
.cover-page th { width: 160px; }
.confidential-note { color: #777; font-size: 10px; margin-top: 24px; }
body { font-family: -apple-system, "Segoe UI", Roboto, Helvetica, Arial, sans-serif;
       color: #1a1a1a; font-size: 12px; line-height: 1.5; margin: 0; }
h1 { font-size: 24px; margin: 0 0 4px; }
h2 { font-size: 16px; border-bottom: 2px solid #0b3d63; padding-bottom: 4px;
     margin: 24px 0 12px; color: #0b3d63; }
h3 { font-size: 13px; margin: 12px 0 4px; }
.report-header { border-bottom: 3px solid #0b3d63; padding-bottom: 12px; margin-bottom: 8px; }
.brand { display: flex; align-items: center; gap: 12px; }
.logo-placeholder { width: 56px; height: 56px; border: 2px dashed #0b3d63;
     display: flex; align-items: center; justify-content: center; font-weight: 700;
     color: #0b3d63; font-size: 11px; text-align: center; }
.subtitle { color: #555; }
table { width: 100%; border-collapse: collapse; margin: 8px 0; }
th, td { border: 1px solid #ddd; padding: 6px 8px; text-align: left; vertical-align: top; }
th { background: #f2f5f8; }
.badge { display: inline-block; padding: 2px 8px; border-radius: 3px; color: #fff;
     font-weight: 700; font-size: 11px; }
.sev-critical { background: #b00020; }
.sev-high { background: #e65100; }
.sev-medium { background: #f9a825; color: #1a1a1a; }
.sev-low { background: #2e7d32; }
.sev-informational { background: #546e7a; }
.callout { padding: 10px 12px; border-left: 4px solid #0b3d63; background: #f2f5f8; }
.action-required { border-left-color: #b00020; background: #fdecea; }
.finding-card { border: 1px solid #ddd; border-radius: 4px; padding: 10px 12px; margin: 12px 0;
     page-break-inside: avoid; }
.finding-card h3 { margin: 0 0 8px; display: flex; align-items: center; gap: 8px; }
.finding-card h4 { margin: 10px 0 4px; font-size: 11px; color: #555; text-transform: uppercase; }
.evidence-item { margin: 4px 0 8px; }
.evidence-item pre { background: #f7f7f7; border: 1px solid #eee; padding: 6px 8px;
     white-space: pre-wrap; word-break: break-word; font-size: 10.5px; margin: 2px 0 0; }
footer { margin-top: 32px; border-top: 1px solid #ddd; padding-top: 8px;
     color: #777; font-size: 10px; }
"""


def _sev_class(severity: Severity) -> str:
    return f"sev-{severity.name.lower()}"


def _badge(severity: Severity) -> str:
    return f'<span class="badge {_sev_class(severity)}">{escape(severity.label)}</span>'


def _score_narrative(score: float) -> str:
    if score >= 90:
        return "This places the assessed environment in strong standing overall."
    if score >= 70:
        return "This places the assessed environment in generally sound standing, with room for improvement."
    if score >= 40:
        return "This indicates meaningful security gaps that warrant attention."
    return "This indicates serious security exposure that warrants prompt attention."


def _cover_page(report: Report, *, brand_name: str) -> str:
    scan_date = report.generated_at.strftime("%Y-%m-%d")
    rows = {
        "Target": report.target,
        "Assessment Date": scan_date,
        "Scope": report.scope or "Not recorded",
        "Authorized By": report.authorized_by or "Not recorded",
        "Assessment ID": report.assessment_id,
    }
    body = "".join(f"<tr><th>{escape(k)}</th><td>{escape(str(v))}</td></tr>" for k, v in rows.items())
    return (
        '<section class="cover-page">'
        f"<h1>{escape(brand_name)}</h1>"
        '<div class="subtitle">Security Assessment Report</div>'
        f"<table>{body}</table>"
        '<p class="confidential-note">This report is confidential and prepared solely for the '
        "recipient named above. Point-in-time snapshot — see Limitations for scope and caveats.</p>"
        "</section>"
    )


def _limitations(report: Report) -> str:
    """A general, honest limitations statement.

    Per-tool coverage detail (which scanners ran, which were skipped and why)
    is now tracked and rendered separately in Scanner Coverage - this section
    stays about what automated scanning as a method cannot guarantee, not
    about which specific tools executed."""
    return (
        '<section id="limitations">'
        "<h2>Limitations</h2>"
        "<p>This assessment reflects automated scanning of the authorized target "
        f"(<strong>{escape(report.target)}</strong>) at a single point in time "
        f"({escape(report.generated_at.strftime('%Y-%m-%d %H:%M:%S %Z'))}). It does not "
        "constitute a comprehensive security audit. Automated tools carry an inherent risk "
        "of false negatives (real issues not detected) and false positives (flagged issues "
        "that are not actually exploitable) — findings above should be independently verified "
        "before remediation is prioritized on their basis alone. This report does not correlate "
        "findings to specific CVE identifiers or CVSS vectors; where that detail matters, it "
        "should be researched separately for the specific software/version in use. A change to "
        "the target's configuration after this assessment invalidates these results.</p>"
        "</section>"
    )


def _executive_summary(report: Report) -> str:
    verdict = report.verdict
    highest = verdict.highest_severity.label if verdict.highest_severity else "None"
    score = report.executive_score
    action = (
        '<p class="callout action-required"><strong>Action required.</strong> '
        "Remediation is recommended for the issues identified below.</p>"
        if verdict.action_required
        else '<p class="callout">No immediate action is required.</p>'
    )
    return (
        '<section id="executive-summary">'
        "<h2>Executive Summary</h2>"
        f"<p>A security assessment of <strong>{escape(report.target)}</strong> was completed on "
        f"{escape(report.generated_at.strftime('%Y-%m-%d'))}. {escape(verdict.headline)} "
        f"The assessment recorded <strong>{report.total_findings}</strong> finding(s) in total, "
        f"with a highest observed severity of <strong>{escape(highest)}</strong>.</p>"
        f'<p>Overall Risk Score: <strong>{score:.1f} / 100</strong>. '
        f"{escape(_score_narrative(score))} "
        "This score deducts fixed points per finding by severity "
        "(Critical 25, High 10, Medium 5, Low 2) from a 100-point baseline — "
        "a simple, explainable measure, not a formal risk-modeling output.</p>"
        f"{action}"
        "</section>"
    )


def _business_impact(report: Report) -> str:
    """AI-generated, plain-language business-risk framing for Critical/High findings.

    This section serves two roles in the required report structure: the
    "Business Impact" section (per-critical-finding business translation) and
    the "AI-Generated Explanations" section (same content, same graceful
    degradation) — the two ask for the same underlying content at different
    granularity, so this renders it once rather than duplicating identical
    text under two headings.
    """
    # Checks the OBSERVABLE outcome (did any finding actually get a real
    # explanation) rather than report.ai_enabled alone: an AI adapter is
    # always injected in this deployment regardless of whether an API key is
    # configured (ai_enabled=True in both cases), so ai_enabled by itself
    # can't distinguish "AI worked" from "AI was attempted and failed for
    # everything" (e.g. no key). Checking the actual per-finding outcome
    # covers both that case and the "no adapter at all" case correctly. Must
    # be visible regardless of whether this assessment has Critical/High
    # findings — it's the only place "AI-Generated Explanations" graceful
    # degradation is surfaced, so it can't be hidden behind an early return
    # for the no-findings case.
    ai_available = any(e.ai_explanation for e in report.entries)
    ai_status = (
        ""
        if ai_available
        else (
            '<p class="callout">AI-generated, plain-language business-impact explanations are not '
            "available for this report — either no AI provider is configured, or the provider "
            "could not be reached. Configure a provider in Settings to include them in future "
            "reports.</p>"
        )
    )
    critical = [e for e in report.entries if e.severity in (Severity.CRITICAL, Severity.HIGH)]
    if not critical:
        body = (
            "<p>No Critical or High severity findings were identified, so no "
            "business-impact analysis is required for this assessment.</p>"
        )
    else:
        body = "".join(_business_impact_card(e) for e in critical)
    return f'<section id="business-impact"><h2>Business Impact</h2>{ai_status}{body}</section>'


def _business_impact_card(entry: FindingSummary) -> str:
    text = entry.ai_explanation or "The AI provider did not return a business-impact explanation for this finding."
    return (
        '<div class="finding-card">'
        f"<h3>{_badge(entry.severity)} {escape(entry.title)}</h3>"
        f"<p>{escape(text)}</p>"
        "</div>"
    )


_CHART_COLORS: dict[Severity, str] = {
    Severity.CRITICAL: "#b00020",
    Severity.HIGH: "#e65100",
    Severity.MEDIUM: "#f9a825",
    Severity.LOW: "#2e7d32",
    Severity.INFORMATIONAL: "#546e7a",
}


def _severity_distribution_chart(report: Report) -> str:
    """A hand-rolled inline SVG horizontal bar chart — no charting library,
    consistent with this module's pure-stdlib design (WeasyPrint renders
    inline SVG natively)."""
    counts = dict(report.severity_counts)
    present = [(sev, counts[sev]) for sev in _SEVERITY_ORDER if counts.get(sev, 0) > 0]
    if not present:
        return "<p>No findings to chart.</p>"

    max_count = max(count for _, count in present)
    bar_height, gap, label_width, chart_width = 18, 8, 110, 260
    row_height = bar_height + gap
    svg_height = len(present) * row_height
    rows = []
    for i, (sev, count) in enumerate(present):
        y = i * row_height
        width = max(2, round((count / max_count) * chart_width))
        color = _CHART_COLORS[sev]
        rows.append(
            f'<text x="0" y="{y + bar_height - 5}" font-size="11">{escape(sev.label)}</text>'
            f'<rect x="{label_width}" y="{y}" width="{width}" height="{bar_height}" fill="{color}" />'
            f'<text x="{label_width + width + 6}" y="{y + bar_height - 5}" font-size="11">{count}</text>'
        )
    svg_width = label_width + chart_width + 40
    return (
        f'<svg viewBox="0 0 {svg_width} {svg_height}" width="{svg_width}" height="{svg_height}" '
        'xmlns="http://www.w3.org/2000/svg" role="img" aria-label="Severity distribution chart">'
        f"{''.join(rows)}"
        "</svg>"
    )


def _risk_over_time_chart(report: Report) -> str:
    """A hand-rolled inline SVG line chart of this target's score history.

    Degrades honestly when there isn't enough history: fewer than 2 points
    (including this report) means there's nothing to plot a trend from.
    """
    points = [*report.history, HistoryPoint(generated_at=report.generated_at, executive_score=report.executive_score)]
    if len(points) < 2:
        return "<p>Insufficient history to chart a trend — this is the first report for this target.</p>"

    width, height = 340, 140
    left_pad, right_pad, top_pad, bottom_pad = 34, 12, 18, 24
    plot_w = width - left_pad - right_pad
    plot_h = height - top_pad - bottom_pad
    n = len(points)

    def x_of(i: int) -> float:
        return left_pad + (i / (n - 1)) * plot_w

    def y_of(score: float) -> float:
        return top_pad + (1 - score / 100.0) * plot_h

    coords = [(x_of(i), y_of(p.executive_score)) for i, p in enumerate(points)]
    polyline = " ".join(f"{x:.1f},{y:.1f}" for x, y in coords)

    # Y-axis with gridlines/labels at 0/25/50/75/100 so the trend is readable
    # without having to infer values from dot position alone.
    axis_ticks = []
    for score in (0, 25, 50, 75, 100):
        y = y_of(score)
        axis_ticks.append(
            f'<line x1="{left_pad}" y1="{y:.1f}" x2="{width - right_pad}" y2="{y:.1f}" '
            'stroke="#eee" stroke-width="1" />'
            f'<text x="{left_pad - 6}" y="{y + 3:.1f}" font-size="9" text-anchor="end" fill="#777">{score}</text>'
        )

    dots_and_labels = []
    for i, ((x, y), p) in enumerate(zip(coords, points, strict=True)):
        if i == 0:
            # The first point sits at the same x-position as the y-axis
            # gridline labels (0/25/50/75/100), which all live in that same
            # left-edge column — an above/below vertical offset alone always
            # ends up colliding with SOME gridline label sooner or later
            # (fixing a collision with "100" just relocated it to "75").
            # Placing this one label to the right of its dot clears the axis
            # column entirely, regardless of score.
            label_x, label_y, anchor = x + 10, y - 6, "start"
        else:
            label_x, label_y, anchor = x, (y - 8 if y - 8 > top_pad + 10 else y + 14), "middle"
        dots_and_labels.append(
            f'<circle cx="{x:.1f}" cy="{y:.1f}" r="3" fill="#0b3d63" />'
            f'<text x="{label_x:.1f}" y="{label_y:.1f}" font-size="10" text-anchor="{anchor}" '
            f'font-weight="700" fill="#0b3d63">{p.executive_score:.0f}</text>'
        )

    first_label = points[0].generated_at.strftime("%Y-%m-%d")
    last_label = points[-1].generated_at.strftime("%Y-%m-%d")
    return (
        f'<svg viewBox="0 0 {width} {height}" width="{width}" height="{height}" '
        'xmlns="http://www.w3.org/2000/svg" role="img" aria-label="Risk score over time chart">'
        f"{''.join(axis_ticks)}"
        f'<polyline points="{polyline}" fill="none" stroke="#0b3d63" stroke-width="2" />'
        f"{''.join(dots_and_labels)}"
        f'<text x="{left_pad}" y="{height - 2}" font-size="9">{escape(first_label)}</text>'
        f'<text x="{width - right_pad - 60}" y="{height - 2}" font-size="9">{escape(last_label)}</text>'
        "</svg>"
    )


def _visual_elements(report: Report) -> str:
    return (
        '<section id="visual-elements">'
        "<h2>Visual Elements</h2>"
        "<h3>Severity Distribution</h3>"
        f"{_severity_distribution_chart(report)}"
        "<h3>Risk Score Over Time (this target)</h3>"
        f"{_risk_over_time_chart(report)}"
        "</section>"
    )


def _risk_prioritization(report: Report) -> str:
    """A ranked "fix this first" action list, reusing the already worst-first
    entry ordering plus the severity-based effort heuristic — pure
    presentation over data Units 2-3 already computed, no new domain logic.
    """
    if not report.entries:
        return ""
    items = "".join(
        "<li>"
        f"{_badge(entry.severity)} <strong>{escape(entry.title)}</strong> "
        f"— estimated fix effort: {escape(entry.estimated_effort)}"
        "</li>"
        for entry in report.entries
    )
    return (
        '<section id="risk-prioritization">'
        "<h2>Risk Prioritization</h2>"
        "<p>Findings below are ordered most-severe first — address them in this order.</p>"
        f"<ol>{items}</ol>"
        "</section>"
    )


def _affected_assets(report: Report) -> str:
    """Scope summary: what was actually assessed.

    Assessments here target a single value (IP/hostname/URL/network), so
    this stays a one-row table honestly reflecting that — it does not imply
    a multi-asset scan scope the current model doesn't have.
    """
    return (
        '<section id="affected-assets">'
        "<h2>Affected Assets Summary</h2>"
        "<table><thead><tr><th>Target</th><th>Findings</th></tr></thead>"
        f"<tbody><tr><td>{escape(report.target)}</td><td>{report.total_findings}</td></tr></tbody></table>"
        "</section>"
    )


def _assessment_information(report: Report) -> str:
    scan_date = report.generated_at.strftime("%Y-%m-%d %H:%M:%S %Z")
    rows = {
        "Target": report.target,
        "Assessment ID": report.assessment_id,
        "Scan Date": scan_date,
        "Assessment Status": _ASSESSMENT_STATUS,
    }
    body = "".join(f"<tr><th>{escape(k)}</th><td>{escape(str(v))}</td></tr>" for k, v in rows.items())
    return f'<section id="assessment-information"><h2>Assessment Information</h2><table>{body}</table></section>'


# Internal error framing that must never reach a customer-facing report
# verbatim: the "[CODE] " prefix every KingSecError.__str__ adds, and the
# "unexpected error in plugin 'x': " wrapper the orchestrator adds when a
# plugin raises something it didn't already recognise.
_ERROR_CODE_PREFIX = re.compile(r"^\[[A-Z]+-[A-Z]+-\d+\]\s*")
_PLUGIN_WRAPPER_PREFIX = re.compile(r"^unexpected error in plugin '[^']+':\s*")


def _clean_scanner_reason(reason: str) -> str:
    """Strip internal error-code/wrapper framing, leaving the factual reason."""
    cleaned = _PLUGIN_WRAPPER_PREFIX.sub("", reason)
    cleaned = _ERROR_CODE_PREFIX.sub("", cleaned)
    return cleaned


def _scanner_summary(report: Report) -> str:
    """Scanner coverage: which scanners ran, and why any didn't.

    Groups scanners sharing the same status and reason into one sentence
    (e.g. "Nuclei, Nikto: not run (binary not found)") rather than a
    one-row-per-scanner table, matching this report's factual, grouped tone
    elsewhere (Executive Summary, Conclusion). Reads sensibly whether the
    assessment used a profile (some scanners excluded by selection) or not
    (every compatible scanner was attempted).
    """
    if not report.scanner_summary:
        return (
            '<section id="scanner-coverage">'
            "<h2>Scanner Coverage</h2>"
            "<p>No scanner outcome was recorded for this assessment.</p>"
            "</section>"
        )

    groups: dict[tuple[str, str], list[str]] = {}
    order: list[tuple[str, str]] = []
    for s in report.scanner_summary:
        if s.status == "completed":
            detail = f"{s.findings_count} finding" + ("" if s.findings_count == 1 else "s")
        else:
            detail = _clean_scanner_reason(s.skipped_reason) if s.skipped_reason else "did not complete"
        key = (s.status, detail)
        groups.setdefault(key, []).append(s.name)
        if key not in order:
            order.append(key)

    sentences = []
    for status, detail in order:
        names = ", ".join(escape(n) for n in groups[(status, detail)])
        if status == "completed":
            sentences.append(f"{names}: completed, {escape(detail)}.")
        else:
            sentences.append(f"{names}: not run ({escape(detail)}).")

    return (
        '<section id="scanner-coverage">'
        "<h2>Scanner Coverage</h2>"
        f"<p>{' '.join(sentences)}</p>"
        "</section>"
    )


def _risk_summary(report: Report) -> str:
    counts = dict(report.severity_counts)
    rows = "".join(f"<tr><td>{_badge(sev)}</td><td>{counts.get(sev, 0)}</td></tr>" for sev in _SEVERITY_ORDER)
    return (
        '<section id="risk-summary">'
        "<h2>Risk Summary</h2>"
        "<table><thead><tr><th>Severity</th><th>Count</th></tr></thead>"
        f"<tbody>{rows}</tbody></table>"
        "</section>"
    )


def _findings(report: Report) -> str:
    if not report.entries:
        return '<section id="findings"><h2>Findings</h2><p>No findings were recorded for this assessment.</p></section>'
    rows = "".join(
        "<tr>"
        f"<td>{_badge(entry.severity)}</td>"
        f"<td>{escape(entry.title)}</td>"
        f"<td>{escape(entry.status.value)}</td>"
        f"<td>{entry.evidence_count}</td>"
        f"<td>{entry.recommendation_count}</td>"
        "</tr>"
        for entry in report.entries
    )
    return (
        '<section id="findings">'
        "<h2>Findings</h2>"
        "<table><thead><tr>"
        "<th>Severity</th><th>Title</th><th>Status</th>"
        "<th>Evidence</th><th>Recommendations</th>"
        "</tr></thead>"
        f"<tbody>{rows}</tbody></table>"
        "</section>"
    )


def _technical_findings(report: Report, *, target: str) -> str:
    """Detailed per-finding technical write-up: description, facts, evidence.

    CVE and CVSS are rendered as an explicit "Not available" rather than
    omitted, because the current scanning pipeline does not correlate a
    finding to a specific CVE or CVSS vector — this is honest about a real
    data gap rather than fabricating a value.
    """
    if not report.entries:
        return ""
    cards = "".join(_technical_finding_card(entry, target=target) for entry in report.entries)
    return f'<section id="technical-findings"><h2>Technical Findings</h2>{cards}</section>'


def _technical_finding_card(entry: FindingSummary, *, target: str) -> str:
    facts = "".join(
        f"<tr><th>{escape(k)}</th><td>{escape(v)}</td></tr>"
        for k, v in (
            ("Affected Asset", target),
            ("CVE", "Not available — not correlated by the current scan"),
            ("CVSS Score / Vector", "Not available — not correlated by the current scan"),
        )
    )
    description = entry.description.strip() or "No technical description was recorded for this finding."
    evidence_html = (
        "".join(
            '<div class="evidence-item">'
            f"<p><strong>{escape(e.summary)}</strong></p>"
            f"<pre>{escape(e.detail)}</pre>"
            "</div>"
            for e in entry.evidence
        )
        if entry.evidence
        else "<p>No evidence was recorded for this finding.</p>"
    )
    return (
        '<div class="finding-card">'
        f"<h3>{_badge(entry.severity)} {escape(entry.title)}</h3>"
        f"<table>{facts}</table>"
        f"<p>{escape(description)}</p>"
        f"<h4>Evidence</h4>{evidence_html}"
        "</div>"
    )


def _remediation_steps(report: Report) -> str:
    """Concrete remediation guidance per finding, plus a sizing heuristic.

    Findings with no recorded recommendation render an explicit, honest note
    rather than being silently skipped — matching the rest of the report's
    never-fabricate, never-silently-omit discipline.
    """
    if not report.entries:
        return ""
    cards = "".join(_remediation_card(entry) for entry in report.entries)
    return f'<section id="remediation-steps"><h2>Remediation Steps</h2>{cards}</section>'


def _remediation_card(entry: FindingSummary) -> str:
    effective = entry.effective_recommendations
    recs_html = (
        "".join(f"<li><strong>{escape(r.title)}</strong> — {escape(r.description)}</li>" for r in effective)
        if effective
        else "<li>No specific remediation guidance is available for this finding.</li>"
    )
    return (
        '<div class="finding-card">'
        f"<h3>{_badge(entry.severity)} {escape(entry.title)}</h3>"
        f"<p>Estimated fix effort: <strong>{escape(entry.estimated_effort)}</strong> "
        "<span class=\"subtitle\">(severity-based heuristic, not a measured estimate)</span></p>"
        f"<ul>{recs_html}</ul>"
        "</div>"
    )


def _conclusion(report: Report) -> str:
    verdict = report.verdict
    if not report.entries:
        text = "The assessment completed with no findings recorded."
    elif verdict.action_required:
        text = (
            "The assessment identified issues that warrant remediation. "
            "Prioritise the highest-severity findings listed above."
        )
    else:
        text = "The assessment completed. The findings recorded are informational and do not require immediate action."
    return f'<section id="conclusion"><h2>Conclusion</h2><p>{escape(text)}</p></section>'


def _footer(report: Report, brand_name: str) -> str:
    generated = report.generated_at.strftime("%Y-%m-%d %H:%M:%S %Z")
    return (
        "<footer>"
        f"<p>Generated by {escape(brand_name)} on {escape(generated)}. "
        "This report is confidential.</p>"
        "</footer>"
    )


def render_report_html(report: Report, *, brand_name: str = "KingSec") -> str:
    """Render a complete, self-contained HTML report from a domain snapshot.

    Args:
        report: The immutable domain report snapshot.
        brand_name: Company branding placeholder shown in the header/footer.

    Returns:
        A full HTML document as a string (deterministic for a given report).
    """
    title = f"Security Assessment Report — {report.target}"
    header = (
        '<header class="report-header"><div class="brand">'
        f'<div class="logo-placeholder">{escape(brand_name)}</div>'
        f"<div><h1>{escape(brand_name)}</h1>"
        '<div class="subtitle">Security Assessment Report</div></div>'
        "</div></header>"
    )
    return (
        "<!DOCTYPE html>"
        '<html lang="en"><head><meta charset="utf-8">'
        f"<title>{escape(title)}</title>"
        f"<style>{_STYLESHEET}</style></head><body>"
        f"{_cover_page(report, brand_name=brand_name)}"
        f"{header}"
        "<main>"
        f"{_executive_summary(report)}"
        f"{_business_impact(report)}"
        f"{_risk_prioritization(report)}"
        f"{_assessment_information(report)}"
        f"{_scanner_summary(report)}"
        f"{_risk_summary(report)}"
        f"{_findings(report)}"
        f"{_technical_findings(report, target=report.target)}"
        f"{_remediation_steps(report)}"
        f"{_visual_elements(report)}"
        f"{_affected_assets(report)}"
        f"{_limitations(report)}"
        f"{_conclusion(report)}"
        "</main>"
        f"{_footer(report, brand_name)}"
        "</body></html>"
    )
