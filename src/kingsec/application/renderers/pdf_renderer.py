"""PDF Report Renderer — converts Report to a printable PDF document.

Pure formatting, no business logic, no calculations, no analysis.
Uses ReportLab for PDF generation.
"""

from __future__ import annotations

from datetime import UTC
from pathlib import Path
from typing import TYPE_CHECKING, Any

from reportlab.lib import colors  # type: ignore[import-untyped]
from reportlab.lib.enums import TA_CENTER  # type: ignore[import-untyped]
from reportlab.lib.pagesizes import A4  # type: ignore[import-untyped]
from reportlab.lib.styles import ParagraphStyle, getSampleStyleSheet  # type: ignore[import-untyped]
from reportlab.lib.units import cm  # type: ignore[import-untyped]
from reportlab.platypus import (  # type: ignore[import-untyped]
    HRFlowable,
    PageBreak,
    Paragraph,
    SimpleDocTemplate,
    Spacer,
    Table,
    TableStyle,
)

if TYPE_CHECKING:
    from kingsec.application.report import (
        AttackPathSection,
        ExecutiveSummary,
        FindingSection,
        RecommendationSection,
        Report,
        RiskSummary,
    )

# ---------------------------------------------------------------------------
# Severity colours
# ---------------------------------------------------------------------------

_SEVERITY_COLORS: dict[str, colors.Color] = {
    "CRITICAL": colors.HexColor("#8B0000"),
    "HIGH": colors.HexColor("#CC3300"),
    "MEDIUM": colors.HexColor("#CC9900"),
    "LOW": colors.HexColor("#336699"),
    "INFO": colors.HexColor("#666666"),
    "INFORMATIONAL": colors.HexColor("#666666"),
}

_SEVERITY_BG: dict[str, colors.Color] = {
    "CRITICAL": colors.HexColor("#FFE0E0"),
    "HIGH": colors.HexColor("#FFE8D0"),
    "MEDIUM": colors.HexColor("#FFF8D0"),
    "LOW": colors.HexColor("#D0E4F0"),
    "INFO": colors.HexColor("#F0F0F0"),
    "INFORMATIONAL": colors.HexColor("#F0F0F0"),
}

_PAGE_WIDTH, _PAGE_HEIGHT = A4
_MARGIN = 2 * cm


# ---------------------------------------------------------------------------
# Styles
# ---------------------------------------------------------------------------

_STYLES = getSampleStyleSheet()

_COVER_TITLE = ParagraphStyle(
    "CoverTitle",
    parent=_STYLES["Title"],
    fontSize=28,
    leading=34,
    textColor=colors.HexColor("#1a1a1a"),
    spaceAfter=12,
    alignment=TA_CENTER,
)

_COVER_SUBTITLE = ParagraphStyle(
    "CoverSubtitle",
    parent=_STYLES["Normal"],
    fontSize=14,
    leading=18,
    textColor=colors.HexColor("#555555"),
    spaceAfter=6,
    alignment=TA_CENTER,
)

_SECTION_HEADING = ParagraphStyle(
    "SectionHeading",
    parent=_STYLES["Heading1"],
    fontSize=20,
    leading=26,
    textColor=colors.HexColor("#1e3a5f"),
    spaceBefore=20,
    spaceAfter=10,
    borderPadding=4,
)

_SUB_HEADING = ParagraphStyle(
    "SubHeading",
    parent=_STYLES["Heading2"],
    fontSize=14,
    leading=18,
    textColor=colors.HexColor("#374151"),
    spaceBefore=14,
    spaceAfter=6,
)

_BODY = ParagraphStyle(
    "Body",
    parent=_STYLES["Normal"],
    fontSize=10,
    leading=14,
    spaceAfter=6,
)

_BODY_BOLD = ParagraphStyle(
    "BodyBold",
    parent=_BODY,
    fontName="Helvetica-Bold",
)

_TABLE_HEADER = ParagraphStyle(
    "TableHeader",
    parent=_STYLES["Normal"],
    fontSize=9,
    leading=12,
    fontName="Helvetica-Bold",
    textColor=colors.white,
    alignment=TA_CENTER,
)

_TABLE_CELL = ParagraphStyle(
    "TableCell",
    parent=_STYLES["Normal"],
    fontSize=8.5,
    leading=11,
)

_TABLE_CELL_CENTER = ParagraphStyle(
    "TableCellCenter",
    parent=_TABLE_CELL,
    alignment=TA_CENTER,
)

_SEVERITY_TEXT = ParagraphStyle(
    "SeverityText",
    parent=_STYLES["Normal"],
    fontSize=8.5,
    leading=11,
    fontName="Helvetica-Bold",
    alignment=TA_CENTER,
)

_META = ParagraphStyle(
    "Meta",
    parent=_STYLES["Normal"],
    fontSize=9,
    leading=12,
    textColor=colors.HexColor("#888888"),
)

_FOOTER_STYLE = ParagraphStyle(
    "Footer",
    parent=_STYLES["Normal"],
    fontSize=8,
    leading=10,
    textColor=colors.HexColor("#999999"),
    alignment=TA_CENTER,
)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _severity_cell(severity: str) -> Paragraph:
    """Return a coloured severity cell for a table."""
    s = severity.upper().replace(" ", "_") if severity else "INFO"
    colour = _SEVERITY_COLORS.get(s, colors.HexColor("#666666"))
    return Paragraph(
        f'<font color="{colour.hexval()}">{severity}</font>',
        _SEVERITY_TEXT,
    )


def _risk_bar(score: int) -> str:
    """Return a small inline visual bar for a risk score."""
    pct = max(0, min(100, score))
    return f'<font size="8">{"█" * (pct // 10)}{"░" * (10 - pct // 10)}</font>'


def _make_table(
    headers: list[str],
    rows: list[list[str]],
    col_widths: list[float] | None = None,
) -> Table:
    """Create a styled table from headers and rows."""
    header_row = [Paragraph(h, _TABLE_HEADER) for h in headers]
    data = [header_row]
    for row in rows:
        data.append([Paragraph(c, _TABLE_CELL) for c in row])

    t = Table(data, colWidths=col_widths, repeatRows=1, hAlign="LEFT")
    style_cmds: list[Any] = [
        ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#1e3a5f")),
        ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
        ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
        ("FONTSIZE", (0, 0), (-1, 0), 9),
        ("BOTTOMPADDING", (0, 0), (-1, 0), 8),
        ("TOPPADDING", (0, 0), (-1, 0), 8),
        ("GRID", (0, 0), (-1, -1), 0.5, colors.HexColor("#cccccc")),
        ("VALIGN", (0, 0), (-1, -1), "TOP"),
        ("LEFTPADDING", (0, 0), (-1, -1), 6),
        ("RIGHTPADDING", (0, 0), (-1, -1), 6),
        ("TOPPADDING", (0, 1), (-1, -1), 4),
        ("BOTTOMPADDING", (0, 1), (-1, -1), 4),
    ]

    for i in range(1, len(data)):
        if i % 2 == 0:
            style_cmds.append(("BACKGROUND", (0, i), (-1, i), colors.HexColor("#f8f9fa")))

    t.setStyle(TableStyle(style_cmds))
    return t


# ---------------------------------------------------------------------------
# Page template helper
# ---------------------------------------------------------------------------


class _NumberedDocTemplate(SimpleDocTemplate):  # type: ignore[misc]
    """SimpleDocTemplate that adds page numbers to footer."""

    def __init__(self, *args: object, **kwargs: object) -> None:
        super().__init__(*args, **kwargs)
        self._saved_page_nums: list[int] = []

    def afterPage(self) -> None:
        self._saved_page_nums.append(self.page)
        super().afterPage()


# ---------------------------------------------------------------------------
# Renderer
# ---------------------------------------------------------------------------


class PDFReportRenderer:
    """Renders a Report object into a professional PDF document."""

    def render(self, report: Report, path: Path) -> None:
        """Render a Report to a PDF file.

        Args:
            report: The Report object to render.
            path: Destination file path.
        """
        doc = _NumberedDocTemplate(
            str(path),
            pagesize=A4,
            leftMargin=_MARGIN,
            rightMargin=_MARGIN,
            topMargin=2.5 * cm,
            bottomMargin=2.5 * cm,
            title=report.title,
            author="KingSec",
        )

        story: list[object] = []
        self._build_story(story, report)
        doc.build(story)

    def render_bytes(self, report: Report) -> bytes:
        """Render a Report to a PDF bytes object.

        Args:
            report: The Report object to render.

        Returns:
            PDF document as bytes.
        """
        from io import BytesIO

        buf = BytesIO()
        doc = _NumberedDocTemplate(
            buf,
            pagesize=A4,
            leftMargin=_MARGIN,
            rightMargin=_MARGIN,
            topMargin=2.5 * cm,
            bottomMargin=2.5 * cm,
            title=report.title,
            author="KingSec",
        )

        story: list[object] = []
        self._build_story(story, report)
        doc.build(story)
        return buf.getvalue()

    # ------------------------------------------------------------------
    # Story builder
    # ------------------------------------------------------------------

    def _build_story(self, story: list[object], report: Report) -> None:
        self._cover_page(story, report)
        story.append(PageBreak())
        self._executive_summary(story, report)
        story.append(PageBreak())
        self._risk_summary(story, report)
        story.append(PageBreak())
        self._technical_findings(story, report)
        story.append(PageBreak())
        self._attack_paths(story, report)
        story.append(PageBreak())
        self._assets(story, report)
        story.append(PageBreak())
        self._recommendations(story, report)
        story.append(PageBreak())
        self._appendix(story, report)

    # ------------------------------------------------------------------
    # Cover page
    # ------------------------------------------------------------------

    @staticmethod
    def _cover_page(story: list[object], report: Report) -> None:
        story.append(Spacer(1, 6 * cm))
        story.append(
            HRFlowable(
                width="60%",
                thickness=3,
                color=colors.HexColor("#1e3a5f"),
                spaceAfter=20,
                spaceBefore=0,
                hAlign="CENTER",
            )
        )
        story.append(Paragraph(report.title, _COVER_TITLE))
        story.append(Spacer(1, 0.8 * cm))

        ts = report.created_at.astimezone(UTC).strftime("%Y-%m-%d %H:%M:%S UTC")
        story.append(Paragraph(f"Generated: {ts}", _COVER_SUBTITLE))
        story.append(Paragraph(f"Report ID: {report.report_id}", _COVER_SUBTITLE))
        story.append(Spacer(1, 3 * cm))
        story.append(
            HRFlowable(
                width="30%",
                thickness=1,
                color=colors.HexColor("#cccccc"),
                spaceAfter=10,
                spaceBefore=0,
                hAlign="CENTER",
            )
        )
        story.append(
            Paragraph(
                "KingSec Security Assessment Report",
                ParagraphStyle(
                    "CoverOrg",
                    parent=_COVER_SUBTITLE,
                    fontSize=11,
                    textColor=colors.HexColor("#999999"),
                ),
            )
        )

    # ------------------------------------------------------------------
    # Executive Summary
    # ------------------------------------------------------------------

    @staticmethod
    def _executive_summary(story: list[object], report: Report) -> None:
        es: ExecutiveSummary = report.executive_summary
        story.append(Paragraph("Executive Summary", _SECTION_HEADING))
        story.append(
            HRFlowable(
                width="100%",
                thickness=2,
                color=colors.HexColor("#1e3a5f"),
                spaceAfter=12,
            )
        )
        story.append(Paragraph(es.summary_text, _BODY))
        story.append(Spacer(1, 6))

        # Severity count table
        sev_data: list[list[str]] = [
            ["Critical", str(es.critical_count)],
            ["High", str(es.high_count)],
            ["Medium", str(es.medium_count)],
            ["Low", str(es.low_count)],
            ["Informational", str(es.informational_count)],
        ]
        sev_table = Table(
            [["Severity", "Count"], *sev_data],
            colWidths=[8 * cm, 4 * cm],
            repeatRows=1,
            hAlign="LEFT",
        )
        sev_style: list[Any] = [
            ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#1e3a5f")),
            ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
            ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
            ("GRID", (0, 0), (-1, -1), 0.5, colors.HexColor("#cccccc")),
            ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
            ("TOPPADDING", (0, 0), (-1, -1), 6),
            ("BOTTOMPADDING", (0, 0), (-1, -1), 6),
            ("LEFTPADDING", (0, 0), (-1, -1), 8),
        ]
        for i, sev_name in enumerate(["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"]):
            row = i + 1
            color_val = _SEVERITY_BG.get(sev_name, colors.white)
            sev_style.append(("BACKGROUND", (0, row), (0, row), color_val))

        sev_table.setStyle(TableStyle(sev_style))
        story.append(sev_table)
        story.append(Spacer(1, 6))

        # Key metrics
        metrics_data: list[list[str]] = [
            ["Total Findings", str(es.total_findings)],
            ["Total Assets", str(es.total_assets)],
            ["Top Risk Score", str(es.top_risk_score)],
            ["Average Risk Score", f"{es.average_risk_score:.1f}"],
            ["Total Severe (Critical + High)", str(es.total_severe)],
        ]
        metrics_table = Table(
            [["Metric", "Value"], *metrics_data],
            colWidths=[8 * cm, 4 * cm],
            repeatRows=1,
            hAlign="LEFT",
        )
        metrics_table.setStyle(
            TableStyle(
                [
                    ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#1e3a5f")),
                    ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
                    ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
                    ("GRID", (0, 0), (-1, -1), 0.5, colors.HexColor("#cccccc")),
                    ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
                    ("TOPPADDING", (0, 0), (-1, -1), 6),
                    ("BOTTOMPADDING", (0, 0), (-1, -1), 6),
                    ("LEFTPADDING", (0, 0), (-1, -1), 8),
                    ("BACKGROUND", (0, 1), (-1, -1), colors.HexColor("#f8f9fa")),
                ]
            )
        )
        story.append(metrics_table)

    # ------------------------------------------------------------------
    # Risk Summary
    # ------------------------------------------------------------------

    @staticmethod
    def _risk_summary(story: list[object], report: Report) -> None:
        rs: RiskSummary = report.risk_summary
        story.append(Paragraph("Risk Summary", _SECTION_HEADING))
        story.append(
            HRFlowable(
                width="100%",
                thickness=2,
                color=colors.HexColor("#1e3a5f"),
                spaceAfter=12,
            )
        )

        score_data: list[list[str]] = [
            ["Average Score", f"{rs.average_score:.1f} / 100"],
            ["Highest Score", str(rs.highest_score)],
            ["Lowest Score", str(rs.lowest_score)],
        ]
        score_table = Table(
            [["Metric", "Value"], *score_data],
            colWidths=[8 * cm, 4 * cm],
            repeatRows=1,
            hAlign="LEFT",
        )
        score_table.setStyle(
            TableStyle(
                [
                    ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#1e3a5f")),
                    ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
                    ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
                    ("GRID", (0, 0), (-1, -1), 0.5, colors.HexColor("#cccccc")),
                    ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
                    ("TOPPADDING", (0, 0), (-1, -1), 6),
                    ("BOTTOMPADDING", (0, 0), (-1, -1), 6),
                    ("LEFTPADDING", (0, 0), (-1, -1), 8),
                    ("BACKGROUND", (0, 1), (-1, -1), colors.HexColor("#f8f9fa")),
                ]
            )
        )
        story.append(score_table)
        story.append(Spacer(1, 6))

        # Score distribution
        dist = rs.score_distribution
        if dist:
            story.append(Paragraph("Score Distribution", _SUB_HEADING))
            dist_data: list[list[str]] = []
            for label, count in sorted(dist.items(), key=lambda x: -x[1]):
                dist_data.append([label, str(count)])
            dist_table = Table(
                [["Category", "Count"], *dist_data],
                colWidths=[8 * cm, 4 * cm],
                repeatRows=1,
                hAlign="LEFT",
            )
            dist_table.setStyle(
                TableStyle(
                    [
                        ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#1e3a5f")),
                        ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
                        ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
                        ("GRID", (0, 0), (-1, -1), 0.5, colors.HexColor("#cccccc")),
                        ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
                        ("TOPPADDING", (0, 0), (-1, -1), 6),
                        ("BOTTOMPADDING", (0, 0), (-1, -1), 6),
                        ("LEFTPADDING", (0, 0), (-1, -1), 8),
                        ("BACKGROUND", (0, 1), (-1, -1), colors.HexColor("#f8f9fa")),
                    ]
                )
            )
            story.append(dist_table)
            story.append(Spacer(1, 6))

        # Top risk factors
        if rs.top_risk_factors:
            story.append(Paragraph("Top Risk Factors", _SUB_HEADING))
            for factor in rs.top_risk_factors:
                story.append(Paragraph(f"  • {factor}", _BODY))

    # ------------------------------------------------------------------
    # Technical Findings
    # ------------------------------------------------------------------

    @staticmethod
    def _technical_findings(story: list[object], report: Report) -> None:
        fs: FindingSection = report.finding_section
        story.append(Paragraph("Technical Findings", _SECTION_HEADING))
        story.append(
            HRFlowable(
                width="100%",
                thickness=2,
                color=colors.HexColor("#1e3a5f"),
                spaceAfter=12,
            )
        )

        if fs.total_count == 0:
            story.append(Paragraph("No findings were identified.", _BODY))
            return

        headers = ["ID", "Title", "Severity", "Score", "Assets"]
        col_widths = [2 * cm, 5.5 * cm, 2.2 * cm, 1.8 * cm, 4.5 * cm]

        rows: list[list[str]] = []
        for fe in fs.entries:
            assets_str = ", ".join(fe.affected_assets) if fe.affected_assets else "—"
            severity_text = (
                f'<font color="{_SEVERITY_COLORS.get(fe.severity.upper(), "#666666").hexval()}">{fe.severity}</font>'
            )
            rows.append(
                [
                    fe.correlation_id,
                    fe.title,
                    severity_text,
                    str(fe.risk_score),
                    assets_str,
                ]
            )

        t = _make_table(headers, rows, col_widths)
        story.append(t)

    # ------------------------------------------------------------------
    # Attack Paths
    # ------------------------------------------------------------------

    @staticmethod
    def _attack_paths(story: list[object], report: Report) -> None:
        aps: AttackPathSection = report.attack_path_section
        story.append(Paragraph("Attack Paths", _SECTION_HEADING))
        story.append(
            HRFlowable(
                width="100%",
                thickness=2,
                color=colors.HexColor("#1e3a5f"),
                spaceAfter=12,
            )
        )

        if aps.total_paths == 0:
            story.append(Paragraph("No attack paths were identified.", _BODY))
            return

        # Summary metrics
        metrics_data = [
            ["Total Paths", str(aps.total_paths)],
            ["Highest Score", str(aps.highest_score)],
            ["Average Score", f"{aps.average_score:.1f}"],
        ]
        m_table = Table(
            [["Metric", "Value"], *metrics_data],
            colWidths=[8 * cm, 4 * cm],
            repeatRows=1,
            hAlign="LEFT",
        )
        m_table.setStyle(
            TableStyle(
                [
                    ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#1e3a5f")),
                    ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
                    ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
                    ("GRID", (0, 0), (-1, -1), 0.5, colors.HexColor("#cccccc")),
                    ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
                    ("TOPPADDING", (0, 0), (-1, -1), 6),
                    ("BOTTOMPADDING", (0, 0), (-1, -1), 6),
                    ("LEFTPADDING", (0, 0), (-1, -1), 8),
                    ("BACKGROUND", (0, 1), (-1, -1), colors.HexColor("#f8f9fa")),
                ]
            )
        )
        story.append(m_table)
        story.append(Spacer(1, 8))

        # Individual paths
        for i, path in enumerate(aps.graph.paths):
            story.append(
                Paragraph(
                    f"Attack Path {i + 1}: {path.path_id}",
                    _SUB_HEADING,
                )
            )

            path_metrics = [
                ["Score", str(path.attack_score)],
                ["Confidence", f"{path.confidence:.0%}"],
                ["Impact", path.estimated_impact],
                ["Complexity", path.attack_complexity],
                ["Likelihood", path.likelihood],
            ]
            pm_table = Table(
                [["Attribute", "Value"], *path_metrics],
                colWidths=[4 * cm, 8 * cm],
                repeatRows=1,
                hAlign="LEFT",
            )
            pm_table.setStyle(
                TableStyle(
                    [
                        ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#374151")),
                        ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
                        ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
                        ("GRID", (0, 0), (-1, -1), 0.5, colors.HexColor("#cccccc")),
                        ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
                        ("TOPPADDING", (0, 0), (-1, -1), 4),
                        ("BOTTOMPADDING", (0, 0), (-1, -1), 4),
                        ("LEFTPADDING", (0, 0), (-1, -1), 6),
                        ("BACKGROUND", (0, 1), (-1, -1), colors.HexColor("#f8f9fa")),
                    ]
                )
            )
            story.append(pm_table)
            story.append(Spacer(1, 4))

            # Nodes in path
            path_rows: list[list[str]] = []
            for n in path.nodes:
                sev_col = _SEVERITY_COLORS.get(n.severity.upper(), colors.HexColor("#666666"))
                path_rows.append(
                    [
                        n.title,
                        f'<font color="{sev_col.hexval()}">{n.severity}</font>',
                        str(n.risk_score),
                        n.asset or "—",
                    ]
                )

            if path_rows:
                node_table = _make_table(
                    ["Finding", "Severity", "Score", "Asset"],
                    path_rows,
                    [6 * cm, 2.5 * cm, 1.5 * cm, 4 * cm],
                )
                story.append(node_table)

            if path.reasoning:
                story.append(
                    Paragraph(
                        f"<b>Reasoning:</b> {path.reasoning}",
                        _BODY,
                    )
                )

            if path.recommendations:
                story.append(Paragraph("<b>Recommendations:</b>", _BODY_BOLD))
                for r in path.recommendations:
                    story.append(Paragraph(f"  • {r}", _BODY))

            if i < len(aps.graph.paths) - 1:
                story.append(Spacer(1, 6))

    # ------------------------------------------------------------------
    # Assets
    # ------------------------------------------------------------------

    @staticmethod
    def _assets(story: list[object], report: Report) -> None:
        asset_summary = report.asset_summary
        story.append(Paragraph("Assets", _SECTION_HEADING))
        story.append(
            HRFlowable(
                width="100%",
                thickness=2,
                color=colors.HexColor("#1e3a5f"),
                spaceAfter=12,
            )
        )

        if asset_summary.total_assets == 0:
            story.append(Paragraph("No assets were identified.", _BODY))
            return

        headers = ["Asset", "Findings", "Highest Risk", "Avg Risk"]
        col_widths = [5 * cm, 3 * cm, 3 * cm, 3 * cm]
        rows: list[list[str]] = []
        for ae in asset_summary.entries:
            rows.append(
                [
                    ae.asset,
                    str(ae.finding_count),
                    str(ae.highest_risk_score),
                    f"{ae.average_risk_score:.1f}",
                ]
            )

        story.append(_make_table(headers, rows, col_widths))

    # ------------------------------------------------------------------
    # Recommendations
    # ------------------------------------------------------------------

    @staticmethod
    def _recommendations(story: list[object], report: Report) -> None:
        recs: RecommendationSection = report.recommendation_section
        story.append(Paragraph("Recommendations", _SECTION_HEADING))
        story.append(
            HRFlowable(
                width="100%",
                thickness=2,
                color=colors.HexColor("#1e3a5f"),
                spaceAfter=12,
            )
        )

        if recs.total_recommendations == 0:
            story.append(Paragraph("No recommendations available.", _BODY))
            return

        headers = ["Finding", "Severity", "Score", "Recommendations"]
        col_widths = [4 * cm, 2 * cm, 1.5 * cm, 7.5 * cm]
        rows: list[list[str]] = []
        for re in recs.entries:
            sev_col = _SEVERITY_COLORS.get(re.severity.upper(), colors.HexColor("#666666"))
            recs_text = "; ".join(re.recommendations)
            rows.append(
                [
                    re.finding_title,
                    f'<font color="{sev_col.hexval()}">{re.severity}</font>',
                    str(re.risk_score),
                    recs_text,
                ]
            )

        story.append(_make_table(headers, rows, col_widths))

    # ------------------------------------------------------------------
    # Appendix
    # ------------------------------------------------------------------

    @staticmethod
    def _appendix(story: list[object], report: Report) -> None:
        appx = report.appendix
        story.append(Paragraph("Appendix", _SECTION_HEADING))
        story.append(
            HRFlowable(
                width="100%",
                thickness=2,
                color=colors.HexColor("#1e3a5f"),
                spaceAfter=12,
            )
        )

        story.append(
            Paragraph(
                f"Generated by: {appx.generated_by}",
                _BODY,
            )
        )
        ts = appx.generated_at.astimezone(UTC).strftime("%Y-%m-%d %H:%M:%S UTC")
        story.append(Paragraph(f"Generated at: {ts}", _BODY))
        story.append(
            Paragraph(
                f"Total plugins: {appx.total_plugins}",
                _BODY,
            )
        )
        story.append(Spacer(1, 6))

        if appx.scanner_versions:
            story.append(Paragraph("Scanner Versions", _SUB_HEADING))
            scanner_data: list[list[str]] = []
            for name, ver in sorted(appx.scanner_versions.items()):
                ver_str = ver if ver is not None else "—"
                scanner_data.append([name, ver_str])

            s_table = Table(
                [["Scanner", "Version"], *scanner_data],
                colWidths=[6 * cm, 6 * cm],
                repeatRows=1,
                hAlign="LEFT",
            )
            s_table.setStyle(
                TableStyle(
                    [
                        ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#1e3a5f")),
                        ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
                        ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
                        ("GRID", (0, 0), (-1, -1), 0.5, colors.HexColor("#cccccc")),
                        ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
                        ("TOPPADDING", (0, 0), (-1, -1), 6),
                        ("BOTTOMPADDING", (0, 0), (-1, -1), 6),
                        ("LEFTPADDING", (0, 0), (-1, -1), 8),
                        ("BACKGROUND", (0, 1), (-1, -1), colors.HexColor("#f8f9fa")),
                    ]
                )
            )
            story.append(s_table)
