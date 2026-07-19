"""CSV Report Renderer — exports every finding as one CSV row.

Pure formatting, no business logic, no calculations, no analysis.
RFC4180 compliant, UTF-8, deterministic ordering.
"""

from __future__ import annotations

import csv
import io
from pathlib import Path
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from kingsec.application.report import (
        FindingEntry,
        RecommendationSection,
        Report,
    )

# ---------------------------------------------------------------------------
# Column definitions
# ---------------------------------------------------------------------------

_HEADERS: list[str] = [
    "Correlation ID",
    "Finding ID",
    "Title",
    "Severity",
    "Risk Score",
    "Risk Level",
    "Priority",
    "Category",
    "Affected Asset",
    "Scanner",
    "Scanner Version",
    "Description",
    "Evidence",
    "Recommendations",
    "References",
    "Business Impact",
    "Exploit Likelihood",
    "Remediation Complexity",
    "Attack Surface",
    "Technology",
    "Service",
    "Protocol",
    "Port",
    "Operating System",
    "Risk Factors",
    "Discovered At",
]


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _join(items: tuple[str, ...]) -> str:
    """Join tuple items with "; " separator or return empty string."""
    return "; ".join(items) if items else ""


def _scanner_versions(
    scanner_sources: tuple[str, ...],
    versions: dict[str, str | None],
) -> str:
    """Build scanner version string from scanner sources and versions dict."""
    parts: list[str] = []
    for s in scanner_sources:
        ver = versions.get(s)
        if ver:
            parts.append(f"{s} {ver}")
        else:
            parts.append(s)
    return "; ".join(parts) if parts else ""


def _build_recs_lookup(
    section: RecommendationSection,
) -> dict[str, list[str]]:
    lookup: dict[str, list[str]] = {}
    for entry in section.entries:
        lookup[entry.correlation_id] = list(entry.recommendations)
    return lookup


def _row(fe: FindingEntry, recs: dict[str, list[str]],
         versions: dict[str, str | None]) -> list[str]:
    """Build a single CSV row from a FindingEntry."""
    return [
        fe.correlation_id,
        fe.correlation_id,
        fe.title,
        fe.severity,
        str(fe.risk_score),
        fe.risk_level,
        fe.priority,
        fe.category,
        _join(fe.affected_assets),
        _join(fe.scanner_sources),
        _scanner_versions(fe.scanner_sources, versions),
        "",
        "",
        _join(tuple(recs.get(fe.correlation_id, []))),
        "",
        "",
        "",
        "",
        fe.attack_surface or "",
        "",
        fe.service or "",
        fe.protocol or "",
        str(fe.port) if fe.port is not None else "",
        "",
        "",
        "",
    ]


# ---------------------------------------------------------------------------
# Renderer
# ---------------------------------------------------------------------------


class CsvReportRenderer:
    """Renders a Report object to RFC4180-compliant CSV."""

    def render(self, report: Report) -> str:
        """Render a Report to a CSV string."""
        buf = io.StringIO()
        writer = csv.writer(buf, lineterminator="\n")
        writer.writerow(_HEADERS)

        recs = _build_recs_lookup(report.recommendation_section)
        versions = report.appendix.scanner_versions

        for fe in report.finding_section.entries:
            writer.writerow(_row(fe, recs, versions))

        return buf.getvalue()

    def write(self, report: Report, path: Path) -> None:
        """Render and write CSV to a file."""
        path.write_text(self.render(report), encoding="utf-8")
