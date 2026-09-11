"""The report-generation implementation of the application ``ReportGeneratorPort``.

Turns a domain ``Report`` into a ``RenderedReport`` deliverable (PDF by default,
or HTML), delegating all rendering to :class:`ReportRenderer`. The adapter only
ever handles ``bytes`` and metadata — no rendering-library object is exposed.
"""

from __future__ import annotations

from kingsec.application import RenderedReport, ReportGeneratorPort
from kingsec.domain import Report
from kingsec.infrastructure.logging import get_logger

from .errors import ReportGenerationError
from .renderer import ReportRenderer

_logger = get_logger("kingsec.infrastructure.reporting")

_FORMATS = {
    "pdf": ("application/pdf", "pdf"),
    "html": ("text/html; charset=utf-8", "html"),
}


class ReportGeneratorAdapter(ReportGeneratorPort):
    """Renders assessment reports as downloadable PDF or HTML artifacts."""

    def __init__(
        self,
        renderer: ReportRenderer | None = None,
        *,
        output_format: str = "pdf",
        brand_name: str = "KingSec",
    ) -> None:
        """Initialise the adapter.

        Args:
            renderer: The renderer to use (defaulted; brand applied if built here).
            output_format: ``"pdf"`` (default) or ``"html"``.
            brand_name: Company branding placeholder for the default renderer.

        Raises:
            ReportGenerationError: If ``output_format`` is not supported.
        """
        fmt = output_format.lower()
        if fmt not in _FORMATS:
            raise ReportGenerationError(
                f"unsupported report format {output_format!r}; supported: {', '.join(sorted(_FORMATS))}"
            )
        self._format = fmt
        self._renderer = renderer or ReportRenderer(brand_name=brand_name)

    def render(self, report: Report, *, format: str | None = None) -> RenderedReport:
        """Render the report into a deliverable artifact.

        Args:
            report: The domain report snapshot.
            format: Optional per-call override (``"pdf"`` or ``"html"``).
                ``None`` uses the format this adapter was constructed with
                (Phase 2A FIX 7: lets a single running adapter serve either
                format on request instead of the format being fixed for the
                life of the process).

        Returns:
            A ``RenderedReport`` with the artifact bytes, media type, and filename.

        Raises:
            ReportGenerationError: If rendering fails, or ``format`` is unsupported.
        """
        fmt = self._format if format is None else format.lower()
        if fmt not in _FORMATS:
            raise ReportGenerationError(
                f"unsupported report format {format!r}; supported: {', '.join(sorted(_FORMATS))}"
            )
        media_type, extension = _FORMATS[fmt]
        if fmt == "pdf":
            content = self._renderer.to_pdf(report)
        else:
            content = self._renderer.to_html(report).encode("utf-8")

        filename = f"kingsec-report-{report.assessment_id}.{extension}"
        _logger.info(
            "report generated",
            assessment_id=report.assessment_id,
            format=fmt,
            bytes=len(content),
        )
        return RenderedReport(content=content, media_type=media_type, filename=filename)
