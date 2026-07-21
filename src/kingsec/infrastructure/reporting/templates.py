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

from html import escape

from kingsec.domain import Report, Severity

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
@page { size: A4; margin: 2cm; }
* { box-sizing: border-box; }
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
footer { margin-top: 32px; border-top: 1px solid #ddd; padding-top: 8px;
     color: #777; font-size: 10px; }
"""


def _sev_class(severity: Severity) -> str:
    return f"sev-{severity.name.lower()}"


def _badge(severity: Severity) -> str:
    return f'<span class="badge {_sev_class(severity)}">{escape(severity.label)}</span>'


def _executive_summary(report: Report) -> str:
    verdict = report.verdict
    highest = verdict.highest_severity.label if verdict.highest_severity else "None"
    action = (
        '<p class="callout action-required"><strong>Action required.</strong> '
        "Remediation is recommended for the issues identified below.</p>"
        if verdict.action_required
        else '<p class="callout">No immediate action is required.</p>'
    )
    return (
        '<section id="executive-summary">'
        "<h2>Executive Summary</h2>"
        f"<p>{escape(verdict.headline)}</p>"
        f"<p>Total findings: <strong>{report.total_findings}</strong> &middot; "
        f"Highest severity: <strong>{escape(highest)}</strong></p>"
        f"{action}"
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
        f"{header}"
        "<main>"
        f"{_executive_summary(report)}"
        f"{_assessment_information(report)}"
        f"{_risk_summary(report)}"
        f"{_findings(report)}"
        f"{_conclusion(report)}"
        "</main>"
        f"{_footer(report, brand_name)}"
        "</body></html>"
    )
