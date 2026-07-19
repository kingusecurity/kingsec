"""Rendering that isolates the PDF library from the rest of the system.

This module is the ONLY place the PDF rendering library (WeasyPrint) is used. It
exposes ``to_html`` (str) and ``to_pdf`` (bytes) and never returns or raises a
rendering-library object — every such exception is translated to
``ReportGenerationError``. WeasyPrint is imported lazily inside ``to_pdf`` so
importing this module (or rendering only HTML) does not require the PDF library.
"""

from __future__ import annotations

from kingsec.domain import Report
from kingsec.infrastructure.logging import get_logger

from .errors import ReportGenerationError
from .templates import render_report_html

_logger = get_logger("kingsec.infrastructure.reporting")


class ReportRenderer:
    """Renders a domain report to HTML and to PDF, hiding the rendering library."""

    def __init__(self, *, brand_name: str = "KingSec") -> None:
        """Initialise the renderer.

        Args:
            brand_name: Company branding placeholder used in the report.
        """
        self._brand_name = brand_name

    def to_html(self, report: Report) -> str:
        """Render the report to a self-contained HTML string.

        Args:
            report: The domain report snapshot.

        Returns:
            The HTML document.

        Raises:
            ReportGenerationError: If HTML generation fails.
        """
        try:
            return render_report_html(report, brand_name=self._brand_name)
        except Exception as exc:
            raise ReportGenerationError(
                "failed to render report HTML",
                context={"assessment_id": report.assessment_id},
                cause=exc,
            ) from exc

    def to_pdf(self, report: Report) -> bytes:
        """Render the report to PDF bytes (via HTML).

        Args:
            report: The domain report snapshot.

        Returns:
            The PDF document as bytes.

        Raises:
            ReportGenerationError: If HTML or PDF generation fails, or the PDF
                library is unavailable.
        """
        html = self.to_html(report)
        pdf = self._html_to_pdf(html)
        _logger.debug(
            "report rendered", assessment_id=report.assessment_id, bytes=len(pdf)
        )
        return pdf

    def _html_to_pdf(self, html: str) -> bytes:
        """Convert HTML to PDF bytes, containing all library exceptions."""
        try:
            # Lazy import: only needed for PDF, and keeps the heavy dependency
            # out of the import path for HTML-only use.
            from weasyprint import HTML
        except (ImportError, OSError) as exc:
            raise ReportGenerationError(
                "PDF rendering library is not available", cause=exc
            ) from exc
        try:
            result = HTML(string=html).write_pdf()
        except Exception as exc:
            raise ReportGenerationError("failed to render report PDF", cause=exc) from exc
        if result is None:  # pragma: no cover - defensive
            raise ReportGenerationError("PDF rendering produced no output")
        return bytes(result)
