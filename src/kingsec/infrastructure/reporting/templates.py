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

Charts and the risk-score gauge are hand-rolled inline SVG rather than a
charting library: WeasyPrint renders inline SVG natively (confirmed by
rendering every chart in this module end-to-end through the real PDF
pipeline), and it keeps this module's zero-dependency, pure-stdlib design.
"""

from __future__ import annotations

import math
import re
from html import escape

from kingsec.domain import HistoryPoint, Report, ScannerRunSummary, Severity
from kingsec.domain.enums import AssessmentStatus, ScannerRunState, SeverityDemotionReason
from kingsec.domain.report import FindingSummary, failed_scanners_in

# Phase 2A: reports are now generated from either a COMPLETED or a
# COMPLETED_WITH_GAPS assessment (domain-enforced in Report.from_assessment),
# so the status shown must reflect which one this actually is - see
# _assessment_status_label() below.
_ASSESSMENT_STATUS_LABELS: dict[str, str] = {
    "completed": "Completed",
    "completed_with_gaps": "Completed with gaps",
}


def _assessment_status_label(status: AssessmentStatus) -> str:
    return _ASSESSMENT_STATUS_LABELS.get(status.value, status.value)

_SEVERITY_ORDER = (
    Severity.CRITICAL,
    Severity.HIGH,
    Severity.MEDIUM,
    Severity.LOW,
    Severity.INFORMATIONAL,
)

# Self-contained stylesheet. System font stack only (no web fonts) — this
# module stays pure-stdlib, and WeasyPrint's system-font resolution is more
# predictable than shipping/embedding a face. Palette: navy (#0b3d63) as the
# single brand accent throughout headings/rules/gauge track; severity colors
# are the only other saturated colors on the page, reserved exclusively for
# severity so they keep their meaning; everything else is ink/slate greys.
_STYLESHEET = """
@page {
    size: A4; margin: 2cm 2cm 2.4cm;
    @bottom-center { content: "Page " counter(page) " of " counter(pages);
        font-size: 8.5px; letter-spacing: 0.03em; color: #94a3b8; }
}
@page :first {
    margin: 0; @bottom-center { content: none; }
}
* { box-sizing: border-box; }

/* ---- Cover page ------------------------------------------------------- */
.cover-page { break-after: page; height: 29.7cm; position: relative; }
.cover-accent { height: 6px; background: linear-gradient(to right, #1a6fb5, #0b3d63); }
.cover-band { background: #0b3d63; color: #fff; padding: 3.4cm 2cm 2cm; position: relative; }
.cover-shield { position: absolute; top: 1.6cm; right: 1.6cm; opacity: 0.14; }
.cover-wordmark { display: flex; align-items: center; gap: 12px; }
.cover-wordmark svg { flex-shrink: 0; }
.cover-band h1 { font-size: 34px; margin: 0; letter-spacing: -0.01em; color: #fff; }
.cover-band .cover-subtitle { font-size: 13px; margin: 6px 0 0; color: #b9cbdd;
     text-transform: uppercase; letter-spacing: 0.12em; font-weight: 600; }
.cover-body { padding: 1.6cm 2cm 0; }
.cover-target-label { font-size: 10px; text-transform: uppercase; letter-spacing: 0.1em;
     color: #64748b; font-weight: 700; margin: 0 0 6px; }
.cover-target { font-size: 22px; font-weight: 700; color: #0b3d63; margin: 0 0 28px;
     line-height: 1.3; }
.cover-grid { display: flex; flex-wrap: wrap; gap: 18px 28px; }
.cover-grid > div { flex: 0 0 46%; }
.cover-grid > div.full { flex: 0 0 100%; }
.cover-field-label { font-size: 9.5px; text-transform: uppercase; letter-spacing: 0.08em;
     color: #94a3b8; font-weight: 700; margin: 0 0 3px; }
.cover-field-value { font-size: 13px; color: #1e293b; font-weight: 600; margin: 0; }
.cover-field-value.mono { font-family: "SF Mono", "Consolas", "Roboto Mono", monospace;
     font-size: 11.5px; font-weight: 500; word-break: break-all; }
.confidential-note { color: #94a3b8; font-size: 9.5px; margin: 40px 0 0; padding-top: 14px;
     border-top: 1px solid #e2e8f0; position: absolute; bottom: 2cm; left: 2cm; right: 2cm; }
/* Phase 2A FIX 4: cover-page scanner coverage callout. Stays within the
   navy/slate palette (no new saturated color) per this stylesheet's own
   rule that severity is the only reserved use of color - prominence here
   comes from border weight, uppercase label, and position, not hue. */
.coverage-alert { margin: 22px 0 0; padding: 14px 16px; border-radius: 3px;
     border: 1.5px solid #0b3d63; background: #eef4f9; }
.coverage-alert-title { font-size: 12px; font-weight: 700; margin: 0 0 6px;
     text-transform: uppercase; letter-spacing: 0.04em; color: #0b3d63; }
.coverage-alert p { margin: 0 0 4px; font-size: 11px; line-height: 1.5; color: #1e293b; }
.coverage-alert p:last-child { margin-bottom: 0; }
.coverage-alert--ok { border-color: #cbd5e1; background: #f8fafc; }
.coverage-alert--ok .coverage-alert-title { color: #475569; }

/* ---- Body typography --------------------------------------------------- */
body { font-family: -apple-system, "Segoe UI", Roboto, Helvetica, Arial, sans-serif;
       color: #1e293b; font-size: 12px; line-height: 1.55; margin: 0; }
h1 { font-size: 24px; margin: 0 0 4px; letter-spacing: -0.01em; }
h2 { font-size: 15px; border-bottom: 2px solid #0b3d63; padding-bottom: 6px;
     margin: 30px 0 14px; color: #0b3d63; letter-spacing: -0.005em; }
section:first-of-type h2 { margin-top: 4px; }
h3 { font-size: 13px; margin: 12px 0 4px; color: #1e293b; }
h4 { font-size: 10.5px; }
p { margin: 0 0 8px; }
.report-header { border-bottom: 3px solid #0b3d63; padding-bottom: 12px; margin-bottom: 4px; }
.brand { display: flex; align-items: center; gap: 12px; }
.logo-placeholder { width: 40px; height: 40px; border-radius: 8px; background: #0b3d63;
     display: flex; align-items: center; justify-content: center; font-weight: 700;
     color: #fff; font-size: 10px; text-align: center; }
.report-header h1 { font-size: 18px; color: #0b3d63; }
.subtitle { color: #64748b; }
.report-header .subtitle { font-size: 10.5px; text-transform: uppercase; letter-spacing: 0.08em;
     font-weight: 600; }

/* ---- Tables ------------------------------------------------------------ */
table { width: 100%; border-collapse: collapse; margin: 10px 0 16px; font-size: 11.5px; }
th, td { border-bottom: 1px solid #e2e8f0; padding: 8px 10px; text-align: left; vertical-align: top; }
th { background: #f1f5f9; color: #475569; font-size: 10px; text-transform: uppercase;
     letter-spacing: 0.05em; font-weight: 700; border-bottom: 2px solid #cbd5e1; }
tbody tr:nth-child(even) { background: #f8fafc; }
tr { page-break-inside: avoid; }
#assessment-information, #risk-summary, #affected-assets { page-break-inside: avoid; }

/* ---- Severity badges ---------------------------------------------------- */
.badge { display: inline-block; padding: 3px 10px; border-radius: 10px; color: #fff;
     font-weight: 700; font-size: 10px; letter-spacing: 0.02em; }
.sev-critical { background: #b00020; }
.sev-high { background: #e65100; }
.sev-medium { background: #f9a825; color: #1a1a1a; }
.sev-low { background: #2e7d32; }
.sev-informational { background: #546e7a; }

/* ---- Callouts, cards ----------------------------------------------------- */
.callout { padding: 12px 14px; border-radius: 6px; border-left: 4px solid #0b3d63; background: #f1f5f9; margin: 0 0 10px; }
.action-required { border-left-color: #b00020; background: #fdecea; }
.action-critical { border-left-color: #b00020; background: #fdecea; }
.action-high { border-left-color: #e65100; background: #fde6d8; }
.finding-card { border: 1px solid #e2e8f0; border-radius: 8px; padding: 12px 14px; margin: 14px 0;
     page-break-inside: avoid; background: #fff; }
.finding-card h3 { margin: 0 0 10px; display: flex; align-items: center; gap: 8px; }
.finding-card h4 { margin: 10px 0 4px; font-size: 10.5px; color: #64748b; text-transform: uppercase;
     letter-spacing: 0.05em; }
.finding-card table { margin: 6px 0 10px; }
.evidence-item { margin: 4px 0 8px; }
.evidence-item pre { background: #f8fafc; border: 1px solid #e2e8f0; border-radius: 4px;
     padding: 8px 10px; white-space: pre-wrap; word-break: break-word; font-size: 10.5px; margin: 2px 0 0; }

/* ---- Risk score gauge ---------------------------------------------------- */
.score-panel { display: flex; align-items: center; gap: 20px; margin: 10px 0 14px;
     padding: 14px 16px; border: 1px solid #e2e8f0; border-radius: 8px; background: #fbfcfe; }
.score-panel .score-copy { flex: 1; }
.score-panel .score-copy p { margin: 0; }
.score-band-label { display: inline-block; font-size: 10px; font-weight: 700;
     text-transform: uppercase; letter-spacing: 0.05em; padding: 2px 9px; border-radius: 10px;
     margin-bottom: 6px; }

footer { margin-top: 32px; border-top: 1px solid #e2e8f0; padding-top: 10px;
     color: #94a3b8; font-size: 9.5px; }
"""

_ACCENT = "#1a6fb5"


def _sev_class(severity: Severity) -> str:
    return f"sev-{severity.name.lower()}"


def _badge(severity: Severity) -> str:
    return f'<span class="badge {_sev_class(severity)}">{escape(severity.label)}</span>'


def _score_narrative(score: float) -> str:
    if score >= 90:
        return "This places the assessed environment in strong standing overall."
    if score >= 75:
        return "This places the assessed environment in good standing, with room for improvement."
    if score >= 50:
        return "This indicates a fair security posture with issues that warrant attention."
    if score >= 25:
        return "This indicates a weak security posture with issues that warrant prompt attention."
    return "This indicates serious security exposure that warrants immediate attention."


def _score_band(score: float) -> tuple[str, str]:
    """Map a 0-100 score to (color, band label), aligned with _score_narrative's
    thresholds and reusing the same severity palette used everywhere else in
    the report so the color already carries meaning for the reader.

    Phase 2C Step 2: bands (90-100 Strong | 75-89 Good | 50-74 Fair |
    25-49 Weak | 0-24 Critical) describe the SCORE NUMBER being shown,
    independent of which formula (v1 or v2, see Report.score_version)
    produced it - a v1 report's score is banded the same way a v2 report's
    is, since the bands are a presentation concern about the number, not
    about the formula's identity.
    """
    if score >= 90:
        return "#2e7d32", "Strong"
    if score >= 75:
        return "#7cb342", "Good"
    if score >= 50:
        return "#f9a825", "Fair"
    if score >= 25:
        return "#e65100", "Weak"
    return "#b00020", "Critical"


# Solid (not alpha-blended) light tints for the score-band pill background —
# WeasyPrint's 8-digit #RRGGBBAA hex support is inconsistent across versions,
# so this uses plain opaque hex rather than relying on it.
_SCORE_BAND_TINTS: dict[str, str] = {
    "#2e7d32": "#e6f2e8",
    "#7cb342": "#eef5e3",
    "#f9a825": "#fdf3dc",
    "#e65100": "#fde6d8",
    "#b00020": "#fbdde1",
    "#546e7a": "#e7ebee",
}

# Phase 2A-b: forced band color/label when assessment_status is
# COMPLETED_WITH_GAPS, overriding whatever the raw score would otherwise
# imply. A score computed from 1 of 9 scanners is a measure of one
# scanner, not of security posture - "Sound"/"Strong" and their green/
# amber colors must never appear on a report with incomplete coverage.
# Reuses the neutral slate already used elsewhere in this module for
# "no severity" rather than inventing a new color.
_PARTIAL_COVERAGE_COLOR = "#546e7a"
_PARTIAL_COVERAGE_LABEL = "Partial Coverage"

# Phase 2C Step 2, (d) (approved threshold): zero findings above
# Informational severity scores exactly 100.0 under BOTH formulas -
# Informational carries zero penalty in v1 and retention 1.00 (i.e. "does
# not affect the score") in v2 - so this condition and "the raw score would
# read Strong" are the same condition; there is no other band this override
# could ever suppress. "Strong" implies deep, hard-won assurance; a scan
# that simply found nothing above Informational hasn't earned that reading
# on its own - contrast Original Task-6 Run 4/5 (91.3, Strong, earned via 6
# real Low findings from genuine nmap port enumeration against a target
# with no authentication boundary even applicable) with post-2B-c Run 2/3
# (2 Informational findings and 0 findings respectively, both previously
# 100.0/Strong despite being the LEAST-tested targets in the whole
# dataset). Extends the same override point Phase 2A-b's
# COMPLETED_WITH_GAPS check uses above (same neutral slate color, so the
# reader learns once that this shade means "don't read this as reassuring
# green") rather than building a parallel mechanism - but a DIFFERENT
# label, since "Partial Coverage" would misstate what actually happened
# here (every scanner completed; there was simply nothing to find above
# Informational).
_NO_SIGNAL_COLOR = "#546e7a"
_NO_SIGNAL_LABEL = "No Findings — Coverage Limited"
_NO_SIGNAL_NARRATIVE = (
    "This reflects an absence of findings above Informational severity in "
    "this specific scan, not independent assurance of a strong security "
    "posture — an unauthenticated external scan that finds little may "
    "simply have had little surface to test against (see Limitations for "
    "what this assessment did not examine)."
)


def _is_no_signal(report: Report) -> bool:
    """True when nothing above Informational severity was recorded -
    derived from the report's own severity_counts (never hardcoded), so it
    tracks whatever findings actually exist rather than a fixed count. An
    entirely empty severity_counts (zero findings at all) also counts as
    no-signal: ``all()`` over an empty sequence is True, which is exactly
    the desired behavior here, not an edge-case accident.
    """
    return all(severity is Severity.INFORMATIONAL for severity, count in report.severity_counts if count > 0)

# Phase 2C Step 2, Addition 1 (confirmed correct by explicit user sign-off,
# Phase 2C Step 2 addendum, Addition A): no field anywhere in KingSec's
# scanning domain records whether a scan was credentialed - there is
# nothing on Report to derive this sentence from yet, and inventing a fake
# derivation seam would imply a configurability that doesn't exist. This
# constant IS the single seat of that fact.
#
# THE DAY CREDENTIALED SCANNING IS ADDED: this constant must stop being
# unconditional. _authentication_scope_note() below must start branching on
# real per-assessment state (which fields, TBD by that feature's own
# design) instead of returning this fixed string - update HERE, not by
# editing prose anywhere else in the report. TestAuthenticationScopeDisclosure
# in tests/unit/infrastructure/reporting/test_templates.py enforces that
# every rendered report contains this sentence; that test must be extended
# alongside this constant, not left asserting a claim that stopped being
# universally true.
_AUTHENTICATION_SCOPE_SENTENCE = (
    " This was an unauthenticated external assessment: nothing requiring a login, "
    "session, or credentials was examined, and any application logic reachable only "
    "after authentication was not tested. A clean or low-finding result above "
    "reflects only what is reachable without credentials and says nothing about "
    "what sits behind a login."
)


def _risk_gauge(score: float, color: str) -> str:
    """A hand-rolled inline SVG semicircular gauge for the 0-100 risk score.

    Two concentric arcs sharing one center: a light grey track spanning the
    full 0-100 range, and a colored arc spanning 0-score on top of it.
    ``color`` is supplied by the caller (not derived internally from
    ``_score_band``) so a coverage-incomplete report can force the neutral
    "Partial Coverage" color instead of whatever the raw score would imply
    — the gauge and the surrounding text narrative always agree because
    they share the one decision, made once, by the caller.
    """
    score = max(0.0, min(100.0, score))
    cx, cy, r, sw = 88, 84, 68, 15

    def point(angle_deg: float) -> tuple[float, float]:
        angle_rad = math.radians(angle_deg)
        return cx + r * math.cos(angle_rad), cy - r * math.sin(angle_rad)

    start_x, start_y = point(180.0)
    end_x, end_y = point(0.0)
    track = (
        f'<path d="M {start_x:.1f} {start_y:.1f} A {r} {r} 0 0 1 {end_x:.1f} {end_y:.1f}" '
        f'fill="none" stroke="#e2e8f0" stroke-width="{sw}" stroke-linecap="round" />'
    )

    fill = ""
    if score > 0:
        sweep_angle = 180.0 - (score / 100.0) * 180.0
        cur_x, cur_y = point(sweep_angle)
        fill = (
            f'<path d="M {start_x:.1f} {start_y:.1f} A {r} {r} 0 0 1 {cur_x:.1f} {cur_y:.1f}" '
            f'fill="none" stroke="{color}" stroke-width="{sw}" stroke-linecap="round" />'
        )

    svg_w, svg_h = cx * 2, cy + 14
    return (
        f'<svg viewBox="0 0 {svg_w} {svg_h}" width="{svg_w}" height="{svg_h}" '
        'xmlns="http://www.w3.org/2000/svg" role="img" aria-label="Risk score gauge">'
        f"{track}{fill}"
        f'<text x="{cx}" y="{cy - 6}" font-size="30" font-weight="700" text-anchor="middle" '
        f'font-family="-apple-system, Segoe UI, Roboto, Helvetica, Arial, sans-serif" '
        f'fill="{color}">{score:.0f}</text>'
        f'<text x="{cx}" y="{cy + 15}" font-size="10" text-anchor="middle" fill="#94a3b8" '
        'font-family="-apple-system, Segoe UI, Roboto, Helvetica, Arial, sans-serif">'
        "out of 100</text>"
        "</svg>"
    )


def _shield_icon(*, size: int = 96, color: str = "#ffffff") -> str:
    """A simple hand-drawn shield outline — no icon library, just a path."""
    return (
        f'<svg width="{size}" height="{size}" viewBox="0 0 24 24" fill="none" '
        f'xmlns="http://www.w3.org/2000/svg">'
        f'<path d="M12 2 L21 5.5 V11 C21 16.5 17.2 20.7 12 22 C6.8 20.7 3 16.5 3 11 '
        f'V5.5 Z" stroke="{color}" stroke-width="1.4" stroke-linejoin="round" />'
        f'<path d="M8.3 12.2 L10.7 14.6 L15.7 9.4" stroke="{color}" stroke-width="1.4" '
        f'stroke-linecap="round" stroke-linejoin="round" />'
        "</svg>"
    )


def _cover_field(label: str, value: str, *, mono: bool = False, full: bool = False) -> str:
    css = "cover-field-value mono" if mono else "cover-field-value"
    wrapper_css = "full" if full else ""
    return (
        f'<div class="{wrapper_css}">'
        f'<p class="cover-field-label">{escape(label)}</p>'
        f'<p class="{css}">{escape(value)}</p>'
        "</div>"
    )


def _coverage_status_block(report: Report) -> str:
    """Cover-page scanner coverage callout, for a non-technical SME reader.

    Phase 2A FIX 4: the Run #4 reference-case defect was a report that read
    as a clean, scored result while 6 of 9 scheduled scanners never
    executed, with nothing on the cover page (or anywhere else prominent)
    to say so. This block makes that fact impossible to miss - it lives on
    the cover page itself, not an appendix, names every scanner in plain
    English, and its own headline states outright whether coverage was
    complete before the reader ever reaches a score or a finding.
    """
    summary = report.scanner_summary
    if not summary:
        return (
            '<div class="coverage-alert">'
            '<p class="coverage-alert-title">Scanner coverage not recorded</p>'
            "<p>No scanner outcome was recorded for this assessment. "
            "The findings below cannot be assumed complete.</p>"
            "</div>"
        )

    succeeded = [s.name for s in summary if s.status.is_success]
    skipped = [s for s in summary if s.status.is_skip]
    failed = [s for s in summary if not s.status.is_success and not s.status.is_skip]
    total = len(summary)
    incomplete = bool(skipped or failed)

    def _named_with_reasons(entries: list[ScannerRunSummary]) -> str:
        parts = []
        for s in entries:
            reason = _clean_scanner_reason(s.skipped_reason) if s.skipped_reason else "did not complete"
            parts.append(f"{escape(s.name)} ({escape(reason)})")
        return ", ".join(parts)

    lines = [
        f"<strong>{len(succeeded)} of {total}</strong> scanners ran successfully"
        + (f": {escape(', '.join(succeeded))}." if succeeded else ".")
    ]
    if skipped:
        lines.append(f"<strong>{len(skipped)}</strong> did not run: {_named_with_reasons(skipped)}.")
    if failed:
        lines.append(f"<strong>{len(failed)}</strong> failed or timed out: {_named_with_reasons(failed)}.")

    if incomplete:
        headline = f"Incomplete coverage — only {len(succeeded)} of {total} scanners ran"
        css = "coverage-alert"
    else:
        headline = f"Full coverage — all {total} scanners ran successfully"
        css = "coverage-alert coverage-alert--ok"

    return (
        f'<div class="{css}">'
        f'<p class="coverage-alert-title">{escape(headline)}</p>'
        f"<p>{' '.join(lines)}</p>"
        "</div>"
    )


def _cover_page(report: Report, *, brand_name: str) -> str:
    scan_date = report.generated_at.strftime("%Y-%m-%d")
    highest = report.verdict.highest_severity
    band_color = _CHART_COLORS[highest] if highest is not None else "#546e7a"
    fields = (
        _cover_field("Assessment Date", scan_date)
        + _cover_field("Authorized By", report.authorized_by or "Not recorded")
        + _cover_field("Scope", report.scope or "Not recorded", full=True)
        + _cover_field("Assessment ID", report.assessment_id, mono=True, full=True)
    )
    return (
        '<section class="cover-page">'
        f'<div class="cover-accent" style="background: linear-gradient(to right, {band_color}, #0b3d63);"></div>'
        '<div class="cover-band">'
        f'<div class="cover-shield">{_shield_icon(size=140)}</div>'
        '<div class="cover-wordmark">'
        f"{_shield_icon(size=40)}"
        f"<h1>{escape(brand_name)}</h1>"
        "</div>"
        '<p class="cover-subtitle">Security Assessment Report</p>'
        "</div>"
        '<div class="cover-body">'
        '<p class="cover-target-label">Target</p>'
        f'<p class="cover-target">{escape(report.target)}</p>'
        f'<div class="cover-grid">{fields}</div>'
        f"{_coverage_status_block(report)}"
        "</div>"
        '<p class="confidential-note">This report is confidential and prepared solely for the '
        "recipient named above. Point-in-time snapshot — see Limitations for scope and caveats.</p>"
        "</section>"
    )


def _port_coverage_note(report: Report) -> str:
    """Task 4: what nmap's port scan actually covered, for the Limitations
    section - derived from the recorded ScannerRunSummary.port_specification,
    never a hardcoded sentence, so this text cannot silently go stale
    relative to what the scanner actually recorded (see the linkage test,
    test_templates.py).

    Task 4 FIX 1: None now means exactly one thing - genuinely never
    recorded (a row persisted before this field existed at all, or
    before the two-invocation design ran for a URL target). Every REAL
    nmap run, URL or not, now records a real string
    (resolve_port_specification() in nmap.py never returns None any
    more - a non-URL run gets an explicit sentinel, not an absent key).
    Collapsing "nmap's own default was genuinely used" and "we don't
    know what was used" into the same None value - and thus the same
    sentence - was the exact "nothing found vs nothing looked" defect
    already logged in docs/STATUS.md, reintroduced inside the very
    phase that named it. Only a SUCCEEDED nmap entry counts at all - a
    FAILED/SKIPPED nmap must not get any port-coverage claim, known or
    unknown.
    """
    nmap_runs = [s for s in report.scanner_summary if s.scanner_id == "nmap" and s.status.is_success]
    if not nmap_runs:
        return ""
    spec = nmap_runs[0].port_specification
    if spec is None:
        # Genuinely never recorded - never guess what nmap's default was,
        # never imply "nmap's own default" when the record doesn't say so.
        return (
            " Port coverage for this scan was not recorded; treat the port scope as unknown "
            "— a service on any port may or may not have been seen by this assessment."
        )
    # Recorded fact - embed verbatim rather than paraphrase (covers both
    # the non-URL sentinel and a URL target's two-invocation description),
    # so this sentence and the recorded fact can never drift apart.
    return (
        f" Nmap's port scan of this target covered: {escape(spec)}. This is not every "
        "possible port — a service running on a port outside that coverage would not "
        "have been seen by this assessment."
    )


def _rate_limit_note(report: Report) -> str:
    """Phase 2B-c Priority 3: what request-rate limiting actually applied
    during this scan, for the Limitations section - derived from each
    scanner's own recorded ScannerRunSummary.rate_limit_description, same
    standard as _port_coverage_note() above: never a hardcoded sentence,
    never silently drift from what the scanner actually recorded. Only
    SUCCEEDED runs count - a FAILED/SKIPPED scanner never applied any
    rate limit at all. Unlike port coverage (nmap only), more than one
    scanner (ffuf, gobuster) can populate this in the same assessment.
    """
    entries = [
        (s.name, s.rate_limit_description)
        for s in report.scanner_summary
        if s.status.is_success and s.rate_limit_description is not None
    ]
    if not entries:
        return ""
    parts = "; ".join(f"{escape(name)}: {escape(desc)}" for name, desc in entries)
    return (
        f" Request-rate limiting applied during this scan - {parts}. This paces requests "
        "against the target rather than testing it as fast as possible; a real attacker "
        "using a higher, unthrottled request rate was not simulated."
    )


def _severity_demotion_note(report: Report) -> str:
    """Phase 2B-c Priority 1b: disclose when the severity classifier reduced
    a finding's score below what path/status-only scoring would have
    assigned, and why - same standard as _port_coverage_note() above: an
    operator must be able to tell KingSec changed the answer, not just
    trust it silently. Derived from each entry's own recorded
    original_severity/demotion_reason, never a hardcoded count, so this
    text cannot drift from what was actually demoted.
    """
    demoted = [e for e in report.entries if e.demotion_reason is not None]
    if not demoted:
        return ""
    content_type_count = sum(1 for e in demoted if e.demotion_reason is SeverityDemotionReason.CONTENT_TYPE_MISMATCH)
    baseline_shape_count = sum(1 for e in demoted if e.demotion_reason is SeverityDemotionReason.BASELINE_SHAPE_MATCH)
    reasons: list[str] = []
    if content_type_count:
        reasons.append(
            f"{content_type_count} for returning an HTML page instead of the expected file type "
            "(a generic app response, not a confirmed file disclosure)"
        )
    if baseline_shape_count:
        reasons.append(
            f"{baseline_shape_count} for matching the same response shape as most of this scan's "
            "other hits (indicating a catch-all response, not a distinct real finding)"
        )
    return (
        f" This report's severity scoring reduced {len(demoted)} finding"
        f"{'s' if len(demoted) != 1 else ''} below what the path name alone would suggest: "
        f"{'; '.join(reasons)}. These findings are still listed above with their evidence intact "
        "for independent review; only their severity was reduced."
    )


def _authentication_scope_note(report: Report) -> str:
    """Phase 2C Step 2, Addition 1: disclose the unauthenticated scope on
    EVERY report, not only zero-finding ones.

    A clean or low-finding result says nothing about what sits behind a
    login - that gap must be stated regardless of how the scan otherwise
    turned out. The actual sentence lives in _AUTHENTICATION_SCOPE_SENTENCE
    above (the single seat of this fact, with its own comment on what must
    change when credentialed scanning lands) - this function's only job is
    to be the one call site that renders it into the report. Do not inline
    or duplicate the sentence anywhere else.
    """
    del report  # unused: the sentence is unconditional, see the constant's own comment
    return _AUTHENTICATION_SCOPE_SENTENCE


def _limitations(report: Report) -> str:
    """A general, honest limitations statement.

    Per-tool coverage detail (which scanners ran, which were skipped and why)
    is now tracked and rendered separately in Scanner Coverage - this section
    stays about what automated scanning as a method cannot guarantee, not
    about which specific tools executed.

    The CVE/CVSS sentence is conditional: some scanners (Nuclei, Trivy)
    genuinely correlate findings to CVE/CVSS data and it's rendered above
    when present; others (e.g. Nmap's raw port/service banners) do not and
    never will without separate correlation infrastructure this report
    doesn't have. A blanket "this report does not correlate to CVE/CVSS"
    statement would be false for the first case - say precisely what's true
    for whichever this report actually contains.
    """
    if any(e.cve_ids or e.cvss_score is not None for e in report.entries):
        cve_note = (
            "Where a finding's scanner correlates to CVE/CVSS data (Nuclei, Trivy), that "
            "identifier and score are shown above and sourced directly from the scanner's own "
            "vulnerability database — they are not independently re-verified by KingSec. "
            "Findings from scanners that do not correlate to CVE data (e.g. Nmap's raw "
            "port/service banners) show no CVE/CVSS above; that detail would require separate "
            "correlation and should be researched directly for the specific software/version "
            "in use."
        )
    else:
        cve_note = (
            "This report does not correlate findings to specific CVE identifiers or CVSS "
            "vectors; where that detail matters, it should be researched separately for the "
            "specific software/version in use."
        )
    return (
        '<section id="limitations">'
        "<h2>Limitations</h2>"
        "<p>This assessment reflects automated scanning of the authorized target "
        f"(<strong>{escape(report.target)}</strong>) at a single point in time "
        f"({escape(report.generated_at.strftime('%Y-%m-%d %H:%M:%S %Z'))}). It does not "
        "constitute a comprehensive security audit. Automated tools carry an inherent risk "
        "of false negatives (real issues not detected) and false positives (flagged issues "
        "that are not actually exploitable) — findings above should be independently verified "
        f"before remediation is prioritized on their basis alone. {cve_note}"
        f"{_port_coverage_note(report)}{_rate_limit_note(report)}{_severity_demotion_note(report)}"
        f"{_authentication_scope_note(report)} A change to "
        "the target's configuration after this assessment invalidates these results.</p>"
        "</section>"
    )


def _executive_summary(report: Report) -> str:
    verdict = report.verdict
    highest = verdict.highest_severity.label if verdict.highest_severity else "None"
    score = report.executive_score
    incomplete = report.assessment_status is AssessmentStatus.COMPLETED_WITH_GAPS

    if incomplete:
        # Phase 2A-b: a score derived from a fraction of the configured
        # scanners is not a posture measure - force the neutral band/color
        # and state the real denominator, never the reassuring narrative a
        # complete run would get.
        band_color, band_label = _PARTIAL_COVERAGE_COLOR, _PARTIAL_COVERAGE_LABEL
        succeeded_count = sum(1 for s in report.scanner_summary if s.status.is_success)
        total_count = len(report.scanner_summary)
        score_copy = (
            f"Overall Risk Score: <strong>{score:.1f} / 100</strong> — based on "
            f"{succeeded_count} of {total_count} scanners. Not a posture score. "
            "This figure reflects only the scanners that completed and must not be "
            "read as an overall security rating."
        )
    elif report.score_version == "v1":
        # Historical reports scored under the deprecated linear-deduction
        # formula must keep describing THAT formula, not the v2 one that
        # didn't exist when they were generated (domain/report.py,
        # compute_executive_score_v1's own docstring).
        no_signal = _is_no_signal(report)
        band_color, band_label = (_NO_SIGNAL_COLOR, _NO_SIGNAL_LABEL) if no_signal else _score_band(score)
        narrative = _NO_SIGNAL_NARRATIVE if no_signal else escape(_score_narrative(score))
        score_copy = (
            f"Overall Risk Score: <strong>{score:.1f} / 100</strong>. "
            f"{narrative} "
            "This score deducts fixed points per finding by severity "
            "(Critical 25, High 10, Medium 5, Low 2) from a 100-point baseline — "
            "a simple, explainable measure, not a formal risk-modeling output. "
            "(Historical scoring model.)"
        )
    else:
        no_signal = _is_no_signal(report)
        band_color, band_label = (_NO_SIGNAL_COLOR, _NO_SIGNAL_LABEL) if no_signal else _score_band(score)
        narrative = _NO_SIGNAL_NARRATIVE if no_signal else escape(_score_narrative(score))
        score_copy = (
            f"Overall Risk Score: <strong>{score:.1f} / 100</strong>. "
            f"{narrative} "
            "This score applies a fixed retention percentage per finding by severity, "
            "multiplicatively, from a 100-point baseline — bounded and never fully "
            "exhausted, so remediating findings always raises it. A simple, "
            "explainable measure, not a formal risk-modeling output."
        )

    urgent_note = _urgent_action_note(report)
    # Phase 2C Step 2, FIX 4: real report evidence showed the Critical/High
    # framing ("...immediate remediation required.") immediately followed,
    # two lines later, by the weaker generic "Action required. Remediation
    # is recommended for the issues identified below." - the second dilutes
    # the first rather than reinforcing it. Suppressed whenever the urgent
    # framing already fired: it already states action is required, more
    # specifically and more strongly, so the generic callout adds nothing
    # and only softens the message. Reports with no Critical/High finding
    # (e.g. Medium/Low-only, which still set verdict.action_required) are
    # unaffected - they never had urgent framing to begin with.
    action = (
        ""
        if urgent_note
        else (
            '<p class="callout action-required"><strong>Action required.</strong> '
            "Remediation is recommended for the issues identified below.</p>"
            if verdict.action_required
            else '<p class="callout">No immediate action is required.</p>'
        )
    )
    score_panel = (
        '<div class="score-panel">'
        f"{_risk_gauge(score, band_color)}"
        '<div class="score-copy">'
        f'<span class="score-band-label" style="background: {_SCORE_BAND_TINTS[band_color]}; color: {band_color};">'
        f"{escape(band_label)}</span>"
        f"<p>{score_copy}</p>"
        "</div>"
        "</div>"
    )
    return (
        '<section id="executive-summary">'
        "<h2>Executive Summary</h2>"
        f"<p>A security assessment of <strong>{escape(report.target)}</strong> was completed on "
        f"{escape(report.generated_at.strftime('%Y-%m-%d'))}. {escape(verdict.headline)} "
        f"The assessment recorded <strong>{report.total_findings}</strong> finding(s) in total, "
        f"with a highest observed severity of <strong>{escape(highest)}</strong>.</p>"
        f"{urgent_note}"
        f"{score_panel}"
        f"{action}"
        "</section>"
    )


def _urgent_action_note(report: Report) -> str:
    """Phase 2C Step 2, Addition 2: a Critical (or High) finding forces an
    unconditional act-now callout, independent of the blended score/band.

    From the Phase 2C Step 1 calibration report: one confirmed Critical
    blended with 25 Informational findings into a single "Fair, 51.7"
    number risks an SME reading "schedule it for next sprint" when the
    honest message is "an attacker can log in right now." The band label
    must never be the only carrier of that fact - this renders above it,
    unconditionally, driven by the report's own recorded severity counts
    (never a hardcoded claim), and stacks independently for Critical and
    High so neither masks the other.
    """
    parts: list[str] = []
    if report.count_for(Severity.CRITICAL) > 0:
        parts.append(
            '<p class="callout action-critical"><strong>Critical finding(s) present — '
            "immediate remediation required.</strong> At least one Critical-severity "
            "finding was confirmed in this assessment. This requires action before any "
            "other prioritization, independent of the score below.</p>"
        )
    if report.count_for(Severity.HIGH) > 0:
        parts.append(
            '<p class="callout action-high"><strong>High-severity finding(s) present — '
            "prompt remediation recommended.</strong> At least one High-severity finding "
            "was confirmed in this assessment and should be addressed promptly.</p>"
        )
    return "".join(parts)


def _business_impact(report: Report) -> str:
    """Plain-language business-risk framing for Critical/High findings.

    Task 4 FIX 2: this is a customer deliverable, and an optional
    integration the assessor has or hasn't configured is internal
    plumbing - never something the customer's own report should
    disclose. Previously rendered a top-level "AI-generated... are not
    available for this report" callout whenever no finding had a real
    explanation, INDEPENDENT of whether any explanation was even
    relevant - so a report with no Critical/High findings at all still
    got that sentence, directly contradicting the very next sentence
    ("no business-impact analysis is required"). Fixed: no top-level
    callout about explanation availability at all, ever. If no analysis
    is required, the report says only that.

    Phase 2C Step 2, FIX 3: real report evidence showed a Critical
    finding's card rendering "No business-impact explanation is available
    for this finding." - a customer-facing section whose entire content is
    an absence, the same defect class Task 4 FIX 2 above closed for the
    top-level callout but had not yet closed per-finding. Fixed the same
    way: a finding with no real explanation renders NOTHING here (not
    mentioned in this section at all), and if none of the Critical/High
    findings have a real explanation, the whole section is omitted -
    never a card, or a section, whose content is only its own absence.
    """
    critical = [e for e in report.entries if e.severity in (Severity.CRITICAL, Severity.HIGH)]
    if not critical:
        body = (
            "<p>No Critical or High severity findings were identified, so no "
            "business-impact analysis is required for this assessment.</p>"
        )
        return f'<section id="business-impact"><h2>Business Impact</h2>{body}</section>'

    cards = "".join(_business_impact_card(e) for e in critical if e.ai_explanation)
    if not cards:
        return ""
    return f'<section id="business-impact"><h2>Business Impact</h2>{cards}</section>'


def _business_impact_card(entry: FindingSummary) -> str:
    # Only ever called for a finding that HAS a real ai_explanation - see
    # _business_impact()'s own docstring for why findings without one are
    # no longer rendered here at all.
    return (
        '<div class="finding-card">'
        f"<h3>{_badge(entry.severity)} {escape(entry.title)}</h3>"
        f"<p>{escape(entry.ai_explanation or '')}</p>"
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
    inline SVG natively). Each bar sits on a full-width light track so the
    proportion reads at a glance even for the smallest count, not just
    relative to the longest bar."""
    counts = dict(report.severity_counts)
    present = [(sev, counts[sev]) for sev in _SEVERITY_ORDER if counts.get(sev, 0) > 0]
    if not present:
        return "<p>No findings to chart.</p>"

    total = sum(count for _, count in present)
    max_count = max(count for _, count in present)
    bar_height, gap, label_width, chart_width = 20, 12, 112, 280
    row_height = bar_height + gap
    svg_height = len(present) * row_height - gap + 6
    rows = []
    for i, (sev, count) in enumerate(present):
        y = i * row_height
        width = max(3, round((count / max_count) * chart_width))
        color = _CHART_COLORS[sev]
        pct = round((count / total) * 100)
        rows.append(
            f'<text x="0" y="{y + bar_height - 6}" font-size="11" font-weight="600" '
            f'fill="#1e293b">{escape(sev.label)}</text>'
            f'<rect x="{label_width}" y="{y}" width="{chart_width}" height="{bar_height}" '
            f'rx="4" fill="#f1f5f9" />'
            f'<rect x="{label_width}" y="{y}" width="{width}" height="{bar_height}" rx="4" fill="{color}" />'
            f'<text x="{label_width + chart_width + 10}" y="{y + bar_height - 6}" font-size="11" '
            f'font-weight="700" fill="#1e293b">{count}</text>'
            f'<text x="{label_width + chart_width + 34}" y="{y + bar_height - 6}" font-size="9.5" '
            f'fill="#94a3b8">({pct}%)</text>'
        )
    svg_width = label_width + chart_width + 70
    return (
        f'<p class="subtitle" style="margin-bottom: 10px;">{total} finding(s) total.</p>'
        f'<svg viewBox="0 0 {svg_width} {svg_height}" width="{svg_width}" height="{svg_height}" '
        'xmlns="http://www.w3.org/2000/svg" role="img" aria-label="Severity distribution chart" '
        'font-family="-apple-system, Segoe UI, Roboto, Helvetica, Arial, sans-serif">'
        f"{''.join(rows)}"
        "</svg>"
    )


def _risk_over_time_chart(report: Report) -> str:
    """A hand-rolled inline SVG line chart of this target's score history.

    Degrades honestly when there isn't enough history: fewer than 2
    comparable points (including this report) means there's nothing to
    plot a trend from.

    Phase 2C Step 2, Addition B: a score is meaningless without knowing
    which formula produced it (the same reason Report/HistoryPoint carry
    score_version at all) - the same raw finding distribution can score
    very differently under v1 vs v2 (see the Phase 2C Step 1 calibration
    report), so a single connected line spanning a formula change would
    show apparent improvement or decline that is really just the ruler
    changing. History points scored under a DIFFERENT formula than this
    report are therefore EXCLUDED from the plotted series, not blended or
    merely marked - excluding and disclosing why is the same honesty
    pattern this report already uses elsewhere (e.g. "was not recorded"),
    rather than inventing a new one.
    """
    current_point = HistoryPoint(
        generated_at=report.generated_at,
        executive_score=report.executive_score,
        score_version=report.score_version,
    )
    comparable_history = tuple(h for h in report.history if h.score_version == report.score_version)
    excluded_count = len(report.history) - len(comparable_history)
    exclusion_note = (
        f'<p class="chart-note">{excluded_count} earlier report(s) for this target were scored under a '
        "different formula version and are excluded from this trend — their scores are not directly "
        "comparable to the score(s) shown below.</p>"
        if excluded_count
        else ""
    )

    points = [*comparable_history, current_point]
    if len(points) < 2:
        return (
            "<p>Insufficient history to chart a trend — this is the first report for this target "
            "under the current scoring formula.</p>"
            f"{exclusion_note}"
        )

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
        f"{exclusion_note}"
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
    entry ordering — pure presentation over data Units 2-3 already
    computed, no new domain logic.

    Phase 2C Step 2, FIX 2: previously appended a severity-based "estimated
    fix effort" (e.g. "Large" for changing a default password) - visibly
    wrong on real report evidence, since severity measures impact, not
    engineering effort, and no real effort-tracking data exists anywhere
    upstream to ground an estimate in. Removed rather than replaced with a
    differently-guessed heuristic: a fabricated estimate on a customer
    deliverable is worse than no estimate.
    """
    if not report.entries:
        return ""
    items = "".join(
        f"<li>{_badge(entry.severity)} <strong>{escape(entry.title)}</strong></li>" for entry in report.entries
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
        "Assessment Status": _assessment_status_label(report.assessment_status),
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

    groups: dict[tuple[ScannerRunState, str], list[str]] = {}
    order: list[tuple[ScannerRunState, str]] = []
    for s in report.scanner_summary:
        if s.status.is_success:
            detail = f"{s.findings_count} finding" + ("" if s.findings_count == 1 else "s")
        else:
            detail = _clean_scanner_reason(s.skipped_reason) if s.skipped_reason else "did not complete"
            if s.stderr_excerpt:
                # Phase 2B-c Priority 4 (recurring-class instance nine): the
                # real reason a scanner failed, not just the generic safe
                # message every failure mode shares - see
                # scanner_stderr_excerpt() in application/_support.py.
                detail = f"{detail} — stderr: {s.stderr_excerpt}"
        if s.warnings:
            # Phase 2B Task 2: a scanner can succeed but not quite as
            # configured (e.g. an operator's own port selection silently
            # overridden) - folded into the grouping key itself so two
            # scanners with the same finding count but different warnings
            # never merge into one misleading sentence.
            detail = f"{detail} — {'; '.join(s.warnings)}"
        key = (s.status, detail)
        groups.setdefault(key, []).append(s.name)
        if key not in order:
            order.append(key)

    sentences = []
    for status, detail in order:
        names = ", ".join(escape(n) for n in groups[(status, detail)])
        if status.is_success:
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
        # Phase 2A-b: the raw entry.recommendation_count (len(recommendations))
        # undercounts against what the reader actually sees in the Remediation
        # Steps section, which renders effective_recommendations (real ones,
        # or the generic fallback for well-known finding types) - use the
        # same effective count here so the table never contradicts the
        # section below it.
        f"<td>{len(entry.effective_recommendations)}</td>"
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


_NOT_CORRELATED = "Not available — not correlated by the current scan"


def _format_cve(entry: FindingSummary) -> str:
    return ", ".join(entry.cve_ids) if entry.cve_ids else _NOT_CORRELATED


def _format_cvss(entry: FindingSummary) -> str:
    if entry.cvss_score is None:
        return _NOT_CORRELATED
    if entry.cvss_vector:
        return f"{entry.cvss_score:.1f} ({entry.cvss_vector})"
    return f"{entry.cvss_score:.1f}"


def _technical_finding_card(entry: FindingSummary, *, target: str) -> str:
    facts = "".join(
        f"<tr><th>{escape(k)}</th><td>{escape(v)}</td></tr>"
        for k, v in (
            ("Affected Asset", target),
            ("CVE", _format_cve(entry)),
            ("CVSS Score / Vector", _format_cvss(entry)),
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
        f"<ul>{recs_html}</ul>"
        "</div>"
    )


def _conclusion(report: Report) -> str:
    verdict = report.verdict
    failed = failed_scanners_in(report.scanner_summary)
    if not report.entries:
        if failed:
            names = ", ".join(s.name for s in failed)
            text = (
                "The assessment completed with no findings recorded, but "
                f"{len(failed)} of {len(report.scanner_summary)} configured scanners did not "
                f"complete ({names}). This does not mean the target is clean — see Scanner "
                "Coverage for details."
            )
        else:
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
