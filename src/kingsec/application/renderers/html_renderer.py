"""HTML Report Renderer — converts Report to a standalone HTML5 document.

Pure formatting, no business logic, no calculations, no analysis.
All user content is escaped via stdlib html.escape().
"""

from __future__ import annotations

import html
from datetime import UTC
from pathlib import Path
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from kingsec.application.report import Report

# ---------------------------------------------------------------------------
# Stylesheet (embedded, no external resources)
# ---------------------------------------------------------------------------

_CSS = """
* {
    margin: 0;
    padding: 0;
    box-sizing: border-box;
}
body {
    font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto,
                 Oxygen, Ubuntu, Cantarell, "Helvetica Neue", Arial,
                 sans-serif;
    color: #1a1a1a;
    background: #f5f5f5;
    padding: 0;
    line-height: 1.6;
}
.container {
    max-width: 1100px;
    margin: 0 auto;
    background: #fff;
    padding: 40px 48px;
    min-height: 100vh;
}
h1 {
    font-size: 28px;
    color: #1a1a1a;
    border-bottom: 3px solid #2563eb;
    padding-bottom: 10px;
    margin-bottom: 8px;
}
h2 {
    font-size: 22px;
    color: #1e3a5f;
    border-bottom: 2px solid #e5e7eb;
    padding-bottom: 6px;
    margin: 32px 0 16px;
}
h3 {
    font-size: 18px;
    color: #374151;
    margin: 24px 0 12px;
}
h4 {
    font-size: 16px;
    color: #4b5563;
    margin: 16px 0 8px;
}
.timestamp {
    color: #6b7280;
    font-size: 14px;
    margin-bottom: 24px;
}
.severity-critical { color: #7f1d1d; font-weight: 700; }
.severity-high { color: #b91c1c; font-weight: 600; }
.severity-medium { color: #c2410c; font-weight: 600; }
.severity-low { color: #15803d; font-weight: 600; }
.severity-info { color: #1d4ed8; font-weight: 600; }
table {
    width: 100%;
    border-collapse: collapse;
    margin: 12px 0 20px;
    font-size: 14px;
}
th, td {
    padding: 10px 12px;
    text-align: left;
    border: 1px solid #d1d5db;
}
th {
    background: #f3f4f6;
    font-weight: 600;
    color: #374151;
}
tr:nth-child(even) { background: #f9fafb; }
tr:hover { background: #eff6ff; }
.card {
    background: #f9fafb;
    border: 1px solid #e5e7eb;
    border-radius: 8px;
    padding: 20px;
    margin: 16px 0;
}
.card h3 { margin-top: 0; }
.badge {
    display: inline-block;
    padding: 2px 10px;
    border-radius: 12px;
    font-size: 12px;
    font-weight: 600;
    text-transform: uppercase;
}
.badge-critical { background: #fef2f2; color: #7f1d1d; border: 1px solid #fecaca; }
.badge-high { background: #fff5f5; color: #b91c1c; border: 1px solid #fecaca; }
.badge-medium { background: #fff7ed; color: #c2410c; border: 1px solid #fed7aa; }
.badge-low { background: #f0fdf4; color: #15803d; border: 1px solid #bbf7d0; }
.badge-info { background: #eff6ff; color: #1d4ed8; border: 1px solid #bfdbfe; }
.stats-grid {
    display: grid;
    grid-template-columns: repeat(auto-fill, minmax(200px, 1fr));
    gap: 16px;
    margin: 16px 0;
}
.stat-card {
    background: #f9fafb;
    border: 1px solid #e5e7eb;
    border-radius: 6px;
    padding: 16px;
    text-align: center;
}
.stat-value {
    font-size: 28px;
    font-weight: 700;
    color: #1e3a5f;
    display: block;
}
.stat-label {
    font-size: 12px;
    color: #6b7280;
    text-transform: uppercase;
    margin-top: 4px;
}
.section-divider {
    border: none;
    border-top: 1px solid #e5e7eb;
    margin: 32px 0;
}
ul {
    margin: 8px 0 16px 20px;
    padding: 0;
}
li {
    margin-bottom: 4px;
}
.subtitle {
    color: #6b7280;
    font-size: 14px;
    margin: -4px 0 16px;
}
@media print {
    body { background: #fff; }
    .container { padding: 20px; max-width: 100%; }
    .card { break-inside: avoid; }
}
@media (max-width: 768px) {
    .container { padding: 16px; }
    table { font-size: 12px; }
    th, td { padding: 6px 8px; }
    .stats-grid { grid-template-columns: repeat(2, 1fr); }
}
"""


class HTMLReportRenderer:
    """Renders a Report object into a standalone HTML5 document.

    No external dependencies, no JavaScript, no CDN.
    All user content is escaped via stdlib html.escape().
    """

    def render(self, report: Report) -> str:
        """Render a Report to a complete HTML5 document."""
        parts: list[str] = [
            "<!DOCTYPE html>",
            '<html lang="en">',
            "<head>",
            '<meta charset="utf-8">',
            f"<title>{html.escape(report.title)}</title>",
            "<style>",
            _CSS.strip(),
            "</style>",
            "</head>",
            "<body>",
            '<div class="container">',
        ]
        self._write_header(parts, report)
        parts.append('<hr class="section-divider">')
        self._write_executive_summary(parts, report)
        parts.append('<hr class="section-divider">')
        self._write_risk_summary(parts, report)
        parts.append('<hr class="section-divider">')
        self._write_technical_findings(parts, report)
        parts.append('<hr class="section-divider">')
        self._write_attack_paths(parts, report)
        parts.append('<hr class="section-divider">')
        self._write_assets(parts, report)
        parts.append('<hr class="section-divider">')
        self._write_recommendations(parts, report)
        parts.append('<hr class="section-divider">')
        self._write_appendix(parts, report)
        parts.extend(["</div>", "</body>", "</html>"])
        return "\n".join(parts)

    def write(self, report: Report, path: Path) -> None:
        """Render and write HTML to a file."""
        path.write_text(self.render(report), encoding="utf-8")

    # ------------------------------------------------------------------
    # Header
    # ------------------------------------------------------------------

    @staticmethod
    def _write_header(parts: list[str], report: Report) -> None:
        ts = report.created_at.astimezone(UTC).strftime("%Y-%m-%d %H:%M:%S UTC")
        parts.append(f"<h1>{html.escape(report.title)}</h1>")
        parts.append(f'<p class="timestamp">Generated: {html.escape(ts)}</p>')

    # ------------------------------------------------------------------
    # Executive Summary
    # ------------------------------------------------------------------

    @staticmethod
    def _write_executive_summary(parts: list[str], report: Report) -> None:
        es = report.executive_summary
        parts.append('<section id="executive-summary">')
        parts.append("<h2>Executive Summary</h2>")
        parts.append(f"<p>{html.escape(es.summary_text)}</p>")
        parts.append("<h3>Finding Statistics</h3>")
        parts.append("<table>")
        parts.append("<tr><th>Severity</th><th>Count</th></tr>")
        rows = [
            ("Critical", es.critical_count, "critical"),
            ("High", es.high_count, "high"),
            ("Medium", es.medium_count, "medium"),
            ("Low", es.low_count, "low"),
            ("Informational", es.informational_count, "info"),
        ]
        for label, count, cls in rows:
            parts.append(f'<tr><td><span class="severity-{cls}">{label}</span></td><td>{count}</td></tr>')
        parts.append("</table>")
        parts.append(f"<p><strong>Total findings:</strong> {es.total_findings}</p>")
        parts.append("<h3>Attack Path Summary</h3>")
        ap = report.attack_path_section
        parts.append("<table>")
        parts.append("<tr><th>Metric</th><th>Value</th></tr>")
        parts.append(f"<tr><td>Attack Paths</td><td>{ap.total_paths}</td></tr>")
        parts.append(f"<tr><td>Highest Score</td><td>{ap.highest_score}/100</td></tr>")
        parts.append(f"<tr><td>Average Score</td><td>{ap.average_score:.1f}</td></tr>")
        parts.append("</table>")
        parts.append("<h3>Scope</h3>")
        parts.append("<table>")
        parts.append("<tr><th>Metric</th><th>Value</th></tr>")
        parts.append(f"<tr><td>Total Findings</td><td>{es.total_findings}</td></tr>")
        parts.append(f"<tr><td>Affected Assets</td><td>{es.total_assets}</td></tr>")
        parts.append(f"<tr><td>Top Risk Score</td><td>{es.top_risk_score}/100</td></tr>")
        parts.append(f"<tr><td>Average Risk Score</td><td>{es.average_risk_score:.1f}</td></tr>")
        parts.append("</table>")
        parts.append("</section>")

    # ------------------------------------------------------------------
    # Risk Summary
    # ------------------------------------------------------------------

    @staticmethod
    def _write_risk_summary(parts: list[str], report: Report) -> None:
        rs = report.risk_summary
        parts.append('<section id="risk-summary">')
        parts.append("<h2>Risk Summary</h2>")
        if rs.score_distribution:
            parts.append("<h3>Risk Distribution</h3>")
            parts.append("<table>")
            parts.append("<tr><th>Risk Level</th><th>Count</th></tr>")
            for level in ("Critical", "High", "Medium", "Low", "Informational"):
                count = rs.score_distribution.get(level, 0)
                cls = level.lower()
                if cls == "informational":
                    cls = "info"
                parts.append(f'<tr><td><span class="severity-{cls}">{level}</span></td><td>{count}</td></tr>')
            parts.append("</table>")
        parts.append("<h3>Risk Statistics</h3>")
        parts.append("<table>")
        parts.append("<tr><th>Metric</th><th>Value</th></tr>")
        parts.append(f"<tr><td>Average Score</td><td>{rs.average_score:.1f}</td></tr>")
        parts.append(f"<tr><td>Highest Score</td><td>{rs.highest_score}/100</td></tr>")
        parts.append(f"<tr><td>Lowest Score</td><td>{rs.lowest_score}/100</td></tr>")
        parts.append("</table>")
        if rs.top_risk_factors:
            parts.append("<h3>Top Risk Factors</h3>")
            parts.append("<ul>")
            for factor in rs.top_risk_factors:
                parts.append(f"<li>{html.escape(factor)}</li>")
            parts.append("</ul>")
        parts.append("</section>")

    # ------------------------------------------------------------------
    # Technical Findings
    # ------------------------------------------------------------------

    @staticmethod
    def _write_technical_findings(parts: list[str], report: Report) -> None:
        fs = report.finding_section
        parts.append('<section id="technical-findings">')
        parts.append("<h2>Technical Findings</h2>")
        if not fs.entries:
            parts.append("<p><em>No findings to display.</em></p>")
            parts.append("</section>")
            return

        for fe in fs.entries:
            cls = fe.severity.lower()
            if cls == "informational":
                cls = "info"
            parts.append('<div class="card">')
            parts.append(
                f'<h3>{html.escape(fe.title)} <span class="badge badge-{cls}">{html.escape(fe.severity)}</span></h3>'
            )
            parts.append(f'<p class="subtitle">Correlation ID: <code>{html.escape(fe.correlation_id)}</code></p>')
            parts.append("<table>")
            parts.append("<tr><th>Field</th><th>Value</th></tr>")
            parts.append(
                f"<tr><td><strong>Severity</strong></td>"
                f'<td><span class="severity-{cls}">'
                f"{html.escape(fe.severity)}</span></td></tr>"
            )
            parts.append(f"<tr><td><strong>Risk Score</strong></td><td>{fe.risk_score}/100</td></tr>")
            parts.append(f"<tr><td><strong>Risk Level</strong></td><td>{html.escape(fe.risk_level)}</td></tr>")
            parts.append(f"<tr><td><strong>Priority</strong></td><td>{html.escape(fe.priority)}</td></tr>")
            parts.append(f"<tr><td><strong>Category</strong></td><td>{html.escape(fe.category)}</td></tr>")
            parts.append(f"<tr><td><strong>Confidence</strong></td><td>{fe.confidence:.0%}</td></tr>")
            parts.append(
                f"<tr><td><strong>Scanner(s)</strong></td><td>{html.escape(', '.join(fe.scanner_sources))}</td></tr>"
            )
            svc = fe.service or "N/A"
            parts.append(f"<tr><td><strong>Service</strong></td><td>{html.escape(svc)}</td></tr>")
            port_str = str(fe.port) if fe.port is not None else "N/A"
            parts.append(f"<tr><td><strong>Port</strong></td><td>{html.escape(port_str)}</td></tr>")
            proto = fe.protocol or "N/A"
            parts.append(f"<tr><td><strong>Protocol</strong></td><td>{html.escape(proto)}</td></tr>")
            surface = fe.attack_surface or "N/A"
            parts.append(f"<tr><td><strong>Attack Surface</strong></td><td>{html.escape(surface)}</td></tr>")
            assets_str = ", ".join(fe.affected_assets) if fe.affected_assets else "N/A"
            parts.append(f"<tr><td><strong>Affected Assets</strong></td><td>{html.escape(assets_str)}</td></tr>")
            parts.append("</table>")
            parts.append("</div>")
        parts.append("</section>")

    # ------------------------------------------------------------------
    # Attack Paths
    # ------------------------------------------------------------------

    @staticmethod
    def _write_attack_paths(parts: list[str], report: Report) -> None:
        aps = report.attack_path_section
        parts.append('<section id="attack-paths">')
        parts.append("<h2>Attack Paths</h2>")
        if aps.total_paths == 0 or not aps.graph.paths:
            parts.append("<p><em>No attack paths identified.</em></p>")
            parts.append("</section>")
            return

        parts.append(
            f"<p><strong>Total paths:</strong> {aps.total_paths}<br>"
            f"<strong>Highest score:</strong> {aps.highest_score}/100<br>"
            f"<strong>Average score:</strong> {aps.average_score:.1f}</p>"
        )

        for path in aps.graph.paths:
            parts.append('<div class="card">')
            parts.append(f"<h3>Path: <code>{html.escape(path.path_id)}</code></h3>")
            parts.append(
                f"<p><strong>Attack Score:</strong> {path.attack_score}/100<br>"
                f"<strong>Confidence:</strong> {path.confidence:.0%}<br>"
                f"<strong>Estimated Impact:</strong> "
                f"{html.escape(path.estimated_impact)}<br>"
                f"<strong>Complexity:</strong> "
                f"{html.escape(path.attack_complexity)}<br>"
                f"<strong>Likelihood:</strong> "
                f"{html.escape(path.likelihood)}</p>"
            )
            if path.reasoning:
                parts.append(f"<p><em>{html.escape(path.reasoning)}</em></p>")
            if path.nodes:
                parts.append("<h4>Nodes</h4>")
                parts.append("<table>")
                parts.append(
                    "<tr><th>#</th><th>Title</th><th>Severity</th>"
                    "<th>Surface</th><th>Service</th><th>Port</th>"
                    "<th>Asset</th><th>Risk</th></tr>"
                )
                for i, n in enumerate(path.nodes, 1):
                    surface = n.attack_surface or "-"
                    svc = n.service or "-"
                    port = str(n.port) if n.port is not None else "-"
                    asset = n.asset or "-"
                    parts.append(
                        f"<tr><td>{i}</td>"
                        f"<td>{html.escape(n.title)}</td>"
                        f"<td>{html.escape(n.severity)}</td>"
                        f"<td>{html.escape(surface)}</td>"
                        f"<td>{html.escape(svc)}</td>"
                        f"<td>{html.escape(port)}</td>"
                        f"<td>{html.escape(asset)}</td>"
                        f"<td>{n.risk_score}</td></tr>"
                    )
                parts.append("</table>")
            if path.edges:
                parts.append("<h4>Edges</h4>")
                parts.append("<table>")
                parts.append("<tr><th>Source</th><th>Target</th><th>Relationship</th><th>Confidence</th></tr>")
                for e in path.edges:
                    parts.append(
                        f"<tr><td>{html.escape(e.source_id)}</td>"
                        f"<td>{html.escape(e.target_id)}</td>"
                        f"<td>{html.escape(e.relationship)}</td>"
                        f"<td>{e.confidence:.0%}</td></tr>"
                    )
                parts.append("</table>")
            if path.recommendations:
                parts.append("<h4>Recommendations</h4>")
                parts.append("<ul>")
                for rec in path.recommendations:
                    parts.append(f"<li>{html.escape(rec)}</li>")
                parts.append("</ul>")
            parts.append("</div>")
        parts.append("</section>")

    # ------------------------------------------------------------------
    # Assets
    # ------------------------------------------------------------------

    @staticmethod
    def _write_assets(parts: list[str], report: Report) -> None:
        a = report.asset_summary
        parts.append('<section id="assets">')
        parts.append("<h2>Assets</h2>")
        if not a.entries:
            parts.append("<p><em>No assets identified.</em></p>")
            parts.append("</section>")
            return

        parts.append(
            f"<p><strong>Total assets:</strong> {a.total_assets}<br>"
            f"<strong>Total findings across assets:</strong> "
            f"{a.total_findings}</p>"
        )
        parts.append("<table>")
        parts.append("<tr><th>Asset</th><th>Findings</th><th>Highest Risk</th><th>Avg Risk</th></tr>")
        for entry in a.entries:
            parts.append(
                f"<tr><td>{html.escape(entry.asset)}</td>"
                f"<td>{entry.finding_count}</td>"
                f"<td>{entry.highest_risk_score}/100</td>"
                f"<td>{entry.average_risk_score:.1f}</td></tr>"
            )
        parts.append("</table>")
        parts.append("</section>")

    # ------------------------------------------------------------------
    # Recommendations
    # ------------------------------------------------------------------

    @staticmethod
    def _write_recommendations(parts: list[str], report: Report) -> None:
        rs = report.recommendation_section
        parts.append('<section id="recommendations">')
        parts.append("<h2>Recommendations</h2>")
        if not rs.entries:
            parts.append("<p><em>No recommendations available.</em></p>")
            parts.append("</section>")
            return

        parts.append(f"<p><strong>Total recommendations:</strong> {rs.total_recommendations}</p>")

        for i, entry in enumerate(rs.entries, 1):
            cls = entry.severity.lower()
            if cls == "informational":
                cls = "info"
            parts.append('<div class="card">')
            parts.append(
                f"<h3>{i}. {html.escape(entry.finding_title)} "
                f'<span class="badge badge-{cls}">'
                f"{html.escape(entry.severity)}</span></h3>"
            )
            parts.append("<table>")
            parts.append("<tr><th>Field</th><th>Value</th></tr>")
            parts.append(
                f"<tr><td><strong>Severity</strong></td>"
                f'<td><span class="severity-{cls}">'
                f"{html.escape(entry.severity)}</span></td></tr>"
            )
            parts.append(f"<tr><td><strong>Risk Score</strong></td><td>{entry.risk_score}/100</td></tr>")
            parts.append(
                f"<tr><td><strong>Correlation ID</strong></td>"
                f"<td><code>{html.escape(entry.correlation_id)}</code></td></tr>"
            )
            parts.append("</table>")
            parts.append("<h4>Actions</h4>")
            parts.append("<ul>")
            for rec in entry.recommendations:
                parts.append(f"<li>{html.escape(rec)}</li>")
            parts.append("</ul>")
            parts.append("</div>")
        parts.append("</section>")

    # ------------------------------------------------------------------
    # Appendix
    # ------------------------------------------------------------------

    @staticmethod
    def _write_appendix(parts: list[str], report: Report) -> None:
        app = report.appendix
        parts.append('<section id="appendix">')
        parts.append("<h2>Appendix</h2>")
        if app.scanner_versions:
            parts.append("<h3>Scanner Versions</h3>")
            parts.append("<table>")
            parts.append("<tr><th>Scanner</th><th>Version</th></tr>")
            for scanner in sorted(app.scanner_versions):
                ver = app.scanner_versions[scanner] or "unknown"
                parts.append(f"<tr><td>{html.escape(scanner)}</td><td>{html.escape(ver)}</td></tr>")
            parts.append("</table>")
        parts.append("<h3>Statistics</h3>")
        parts.append("<table>")
        parts.append("<tr><th>Metric</th><th>Value</th></tr>")
        ts = report.technical_summary
        parts.append(f"<tr><td>Normalized Findings</td><td>{ts.total_findings}</td></tr>")
        parts.append(f"<tr><td>Correlated Findings</td><td>{ts.total_correlations}</td></tr>")
        parts.append(f"<tr><td>Enriched Findings</td><td>{ts.total_enriched}</td></tr>")
        parts.append(f"<tr><td>Risk Assessments</td><td>{ts.total_risk_assessments}</td></tr>")
        parts.append("</table>")
        if ts.category_breakdown:
            parts.append("<h4>Category Breakdown</h4>")
            parts.append("<table>")
            parts.append("<tr><th>Category</th><th>Count</th></tr>")
            for cat in sorted(ts.category_breakdown):
                parts.append(f"<tr><td>{html.escape(cat)}</td><td>{ts.category_breakdown[cat]}</td></tr>")
            parts.append("</table>")
        parts.append("<h3>Metadata</h3>")
        parts.append(
            f"<p><strong>Generated by:</strong> "
            f"{html.escape(app.generated_by)}<br>"
            f"<strong>Total scanners:</strong> {app.total_plugins}</p>"
        )
        parts.append("</section>")
