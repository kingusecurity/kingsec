"""Markdown Report Renderer — converts Report to GitHub-compatible Markdown.

Pure formatting, no business logic, no calculations, no analysis.
Deterministic, stable ordering, UTF-8, Unix newlines.
"""

from __future__ import annotations

from datetime import UTC
from pathlib import Path
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from kingsec.application.report import Report


class MarkdownReportRenderer:
    """Renders a Report object into GitHub-compatible Markdown."""

    def render(self, report: Report) -> str:
        """Render a Report to a Markdown string."""
        lines: list[str] = []
        self._write_title(lines, report)
        lines.append("")
        self._write_executive_summary(lines, report)
        lines.append("")
        self._write_risk_summary(lines, report)
        lines.append("")
        self._write_technical_findings(lines, report)
        lines.append("")
        self._write_attack_paths(lines, report)
        lines.append("")
        self._write_assets(lines, report)
        lines.append("")
        self._write_recommendations(lines, report)
        lines.append("")
        self._write_appendix(lines, report)
        lines.append("")
        return "\n".join(lines)

    def write(self, report: Report, path: Path) -> None:
        """Render and write Markdown to a file."""
        path.write_text(self.render(report), encoding="utf-8")

    # ------------------------------------------------------------------
    # Title
    # ------------------------------------------------------------------

    @staticmethod
    def _write_title(lines: list[str], report: Report) -> None:
        lines.append(f"# {report.title}")
        ts = report.created_at.astimezone(UTC).strftime(
            "%Y-%m-%d %H:%M:%S UTC"
        )
        lines.append("")
        lines.append(f"*Generated: {ts}*")
        lines.append("")
        lines.append("---")

    # ------------------------------------------------------------------
    # Executive Summary
    # ------------------------------------------------------------------

    @staticmethod
    def _write_executive_summary(lines: list[str], report: Report) -> None:
        es = report.executive_summary
        lines.append("")
        lines.append("## Executive Summary")
        lines.append("")
        lines.append(es.summary_text)
        lines.append("")
        lines.append("### Finding Statistics")
        lines.append("")
        lines.append("| Severity | Count |")
        lines.append("|----------|-------|")
        lines.append(f"| Critical | {es.critical_count} |")
        lines.append(f"| High     | {es.high_count} |")
        lines.append(f"| Medium   | {es.medium_count} |")
        lines.append(f"| Low      | {es.low_count} |")
        lines.append(f"| Info     | {es.informational_count} |")
        lines.append("")
        lines.append(f"**Total findings:** {es.total_findings}")
        lines.append("")
        ap = report.attack_path_section
        lines.append("### Attack Path Summary")
        lines.append("")
        lines.append("| Metric | Value |")
        lines.append("|--------|-------|")
        lines.append(f"| Attack Paths | {ap.total_paths} |")
        lines.append(f"| Highest Score | {ap.highest_score}/100 |")
        lines.append(f"| Average Score | {ap.average_score:.1f} |")
        lines.append("")
        lines.append("| Metric | Value |")
        lines.append("|--------|-------|")
        lines.append(f"| Findings | {es.total_findings} |")
        lines.append(f"| Assets | {es.total_assets} |")
        lines.append(f"| Top Risk Score | {es.top_risk_score}/100 |")
        lines.append(f"| Avg Risk Score | {es.average_risk_score:.1f} |")
        lines.append("")
        lines.append("---")

    # ------------------------------------------------------------------
    # Risk Summary
    # ------------------------------------------------------------------

    @staticmethod
    def _write_risk_summary(lines: list[str], report: Report) -> None:
        rs = report.risk_summary
        lines.append("")
        lines.append("## Risk Summary")
        lines.append("")
        if rs.score_distribution:
            lines.append("### Risk Distribution")
            lines.append("")
            lines.append("| Risk Level | Count |")
            lines.append("|------------|-------|")
            for level in ("Critical", "High", "Medium", "Low", "Informational"):
                count = rs.score_distribution.get(level, 0)
                if count or level == "Critical":
                    lines.append(f"| {level} | {count} |")
            lines.append("")
        lines.append("### Risk Statistics")
        lines.append("")
        lines.append("| Metric | Value |")
        lines.append("|--------|-------|")
        lines.append(f"| Average Score | {rs.average_score:.1f} |")
        lines.append(f"| Highest Score | {rs.highest_score}/100 |")
        lines.append(f"| Lowest Score  | {rs.lowest_score}/100 |")
        lines.append("")
        if rs.top_risk_factors:
            lines.append("### Top Risk Factors")
            lines.append("")
            for factor in rs.top_risk_factors:
                lines.append(f"- {factor}")
            lines.append("")
        lines.append("---")

    # ------------------------------------------------------------------
    # Technical Findings
    # ------------------------------------------------------------------

    @staticmethod
    def _write_technical_findings(lines: list[str], report: Report) -> None:
        fs = report.finding_section
        lines.append("")
        lines.append("## Technical Findings")
        lines.append("")
        if not fs.entries:
            lines.append("_No findings to display._")
            lines.append("")
            lines.append("---")
            return

        for fe in fs.entries:
            lines.append(f"### {fe.title}")
            lines.append("")
            lines.append(f"**Correlation ID:** `{fe.correlation_id}`")
            lines.append("")
            lines.append("| Field | Value |")
            lines.append("|-------|-------|")
            lines.append(f"| **Severity** | {fe.severity} |")
            lines.append(f"| **Risk Score** | {fe.risk_score}/100 |")
            lines.append(f"| **Risk Level** | {fe.risk_level} |")
            lines.append(f"| **Priority** | {fe.priority} |")
            lines.append(f"| **Category** | {fe.category} |")
            lines.append(f"| **Confidence** | {fe.confidence:.0%} |")
            lines.append(f"| **Scanner(s)** | {', '.join(fe.scanner_sources)} |")
            svc = fe.service or "N/A"
            lines.append(f"| **Service** | {svc} |")
            port_str = str(fe.port) if fe.port is not None else "N/A"
            lines.append(f"| **Port** | {port_str} |")
            proto = fe.protocol or "N/A"
            lines.append(f"| **Protocol** | {proto} |")
            surface = fe.attack_surface or "N/A"
            lines.append(f"| **Attack Surface** | {surface} |")
            assets = ", ".join(fe.affected_assets) if fe.affected_assets else "N/A"
            lines.append(f"| **Affected Assets** | {assets} |")
            lines.append("")

        lines.append("---")

    # ------------------------------------------------------------------
    # Attack Paths
    # ------------------------------------------------------------------

    @staticmethod
    def _write_attack_paths(lines: list[str], report: Report) -> None:
        aps = report.attack_path_section
        lines.append("")
        lines.append("## Attack Paths")
        lines.append("")
        if aps.total_paths == 0 or not aps.graph.paths:
            lines.append("_No attack paths identified._")
            lines.append("")
            lines.append("---")
            return

        lines.append(f"**Total paths:** {aps.total_paths}")
        lines.append("")
        lines.append(f"**Highest score:** {aps.highest_score}/100")
        lines.append("")
        lines.append(f"**Average score:** {aps.average_score:.1f}")
        lines.append("")

        for path in aps.graph.paths:
            lines.append(f"### Path: `{path.path_id}`")
            lines.append("")
            lines.append(f"**Attack Score:** {path.attack_score}/100")
            lines.append("")
            lines.append(f"**Confidence:** {path.confidence:.0%}")
            lines.append("")
            lines.append(f"**Estimated Impact:** {path.estimated_impact}")
            lines.append("")
            lines.append(f"**Complexity:** {path.attack_complexity}")
            lines.append(f"**Likelihood:** {path.likelihood}")
            lines.append("")
            if path.reasoning:
                lines.append(f"_{path.reasoning}_")
                lines.append("")
            if path.nodes:
                lines.append("#### Nodes")
                lines.append("")
                lines.append("| # | Title | Severity | Surface | Service | Port | Asset | Risk |")
                lines.append("|---|-------|----------|---------|---------|------|-------|------|")
                for i, n in enumerate(path.nodes, 1):
                    surface = n.attack_surface or "-"
                    svc = n.service or "-"
                    port = str(n.port) if n.port is not None else "-"
                    asset = n.asset or "-"
                    lines.append(
                        f"| {i} | {n.title} | {n.severity} | {surface} | "
                        f"{svc} | {port} | {asset} | {n.risk_score} |"
                    )
                lines.append("")
            if path.edges:
                lines.append("#### Edges")
                lines.append("")
                lines.append("| Source | Target | Relationship | Confidence |")
                lines.append("|--------|--------|--------------|------------|")
                for e in path.edges:
                    lines.append(
                        f"| {e.source_id} | {e.target_id} | {e.relationship} | "
                        f"{e.confidence:.0%} |"
                    )
                lines.append("")
            if path.recommendations:
                lines.append("#### Recommendations")
                lines.append("")
                for rec in path.recommendations:
                    lines.append(f"- {rec}")
                lines.append("")

        lines.append("---")

    # ------------------------------------------------------------------
    # Assets
    # ------------------------------------------------------------------

    @staticmethod
    def _write_assets(lines: list[str], report: Report) -> None:
        a = report.asset_summary
        lines.append("")
        lines.append("## Assets")
        lines.append("")
        if not a.entries:
            lines.append("_No assets identified._")
            lines.append("")
            lines.append("---")
            return

        lines.append(f"**Total assets:** {a.total_assets}")
        lines.append("")
        lines.append(f"**Total findings across assets:** {a.total_findings}")
        lines.append("")
        lines.append("| Asset | Findings | Highest Risk | Avg Risk |")
        lines.append("|-------|----------|--------------|----------|")
        for entry in a.entries:
            lines.append(
                f"| {entry.asset} | {entry.finding_count} | "
                f"{entry.highest_risk_score}/100 | {entry.average_risk_score:.1f} |"
            )
        lines.append("")
        lines.append("---")

    # ------------------------------------------------------------------
    # Recommendations
    # ------------------------------------------------------------------

    @staticmethod
    def _write_recommendations(lines: list[str], report: Report) -> None:
        rs = report.recommendation_section
        lines.append("")
        lines.append("## Recommendations")
        lines.append("")
        if not rs.entries:
            lines.append("_No recommendations available._")
            lines.append("")
            lines.append("---")
            return

        lines.append(f"**Total recommendations:** {rs.total_recommendations}")
        lines.append("")

        for i, entry in enumerate(rs.entries, 1):
            lines.append(f"### {i}. {entry.finding_title}")
            lines.append("")
            lines.append("| Field | Value |")
            lines.append("|-------|-------|")
            lines.append(f"| **Severity** | {entry.severity} |")
            lines.append(f"| **Risk Score** | {entry.risk_score}/100 |")
            lines.append(f"| **Correlation ID** | `{entry.correlation_id}` |")
            lines.append("")
            lines.append("**Actions:**")
            lines.append("")
            for rec in entry.recommendations:
                lines.append(f"- {rec}")
            lines.append("")

        lines.append("---")

    # ------------------------------------------------------------------
    # Appendix
    # ------------------------------------------------------------------

    @staticmethod
    def _write_appendix(lines: list[str], report: Report) -> None:
        app = report.appendix
        lines.append("")
        lines.append("## Appendix")
        lines.append("")
        if app.scanner_versions:
            lines.append("### Scanner Versions")
            lines.append("")
            lines.append("| Scanner | Version |")
            lines.append("|---------|---------|")
            for scanner in sorted(app.scanner_versions):
                ver = app.scanner_versions[scanner] or "unknown"
                lines.append(f"| {scanner} | {ver} |")
            lines.append("")
        lines.append("### Statistics")
        lines.append("")
        lines.append("| Metric | Value |")
        lines.append("|--------|-------|")
        ts = report.technical_summary
        lines.append(f"| Normalized Findings | {ts.total_findings} |")
        lines.append(f"| Correlated Findings | {ts.total_correlations} |")
        lines.append(f"| Enriched Findings | {ts.total_enriched} |")
        lines.append(f"| Risk Assessments | {ts.total_risk_assessments} |")
        if ts.category_breakdown:
            lines.append("")
            lines.append("#### Category Breakdown")
            lines.append("")
            lines.append("| Category | Count |")
            lines.append("|----------|-------|")
            for cat in sorted(ts.category_breakdown):
                lines.append(f"| {cat} | {ts.category_breakdown[cat]} |")
            lines.append("")
        lines.append("### Metadata")
        lines.append("")
        lines.append(f"**Generated by:** {app.generated_by}")
        lines.append("")
        lines.append(f"**Total scanners:** {app.total_plugins}")
