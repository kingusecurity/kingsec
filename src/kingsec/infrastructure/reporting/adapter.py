"""The report-generation implementation of the application ``ReportGeneratorPort``.

Turns a domain ``Report`` into a ``RenderedReport`` deliverable (PDF by default,
or HTML), delegating all rendering to :class:`ReportRenderer`. The adapter only
ever handles ``bytes`` and metadata — no rendering-library object is exposed.
"""

from __future__ import annotations

import hashlib
from pathlib import Path

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
        cache_dir: Path | None = None,
    ) -> None:
        """Initialise the adapter.

        Args:
            renderer: The renderer to use (defaulted; brand applied if built here).
            output_format: ``"pdf"`` (default) or ``"html"``.
            brand_name: Company branding placeholder for the default renderer.
            cache_dir: Phase 2B-c Priority 2 (5d). When given, rendered bytes
                are cached to a file under this directory, keyed by
                (assessment_id, generated_at, format) - a repeat
                ``GET /reports/{id}/download`` serves the cached artifact
                instead of re-rendering (WeasyPrint) from scratch every
                time. ``None`` (the default) disables caching entirely,
                preserving prior behavior for any caller that doesn't wire
                one up (e.g. tests that construct the adapter directly).
        """
        fmt = output_format.lower()
        if fmt not in _FORMATS:
            raise ReportGenerationError(
                f"unsupported report format {output_format!r}; supported: {', '.join(sorted(_FORMATS))}"
            )
        self._format = fmt
        self._renderer = renderer or ReportRenderer(brand_name=brand_name)
        self._cache_dir = cache_dir

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
        filename = f"kingsec-report-{report.assessment_id}.{extension}"

        cache_path = self._cache_path(report, fmt) if self._cache_dir is not None else None
        if cache_path is not None and cache_path.is_file():
            content = cache_path.read_bytes()
            _logger.info(
                "report served from cache",
                assessment_id=report.assessment_id,
                format=fmt,
                bytes=len(content),
            )
            return RenderedReport(content=content, media_type=media_type, filename=filename)

        if fmt == "pdf":
            content = self._renderer.to_pdf(report)
        else:
            content = self._renderer.to_html(report).encode("utf-8")

        if cache_path is not None:
            cache_path.parent.mkdir(parents=True, exist_ok=True)
            cache_path.write_bytes(content)

        _logger.info(
            "report generated",
            assessment_id=report.assessment_id,
            format=fmt,
            bytes=len(content),
        )
        return RenderedReport(content=content, media_type=media_type, filename=filename)

    def _cache_path(self, report: Report, fmt: str) -> Path:
        """Deterministic cache file path for one (report snapshot, format).

        Keyed on ``generated_at`` (part of the immutable ``Report`` snapshot)
        rather than just ``assessment_id`` - regenerating a report produces a
        new snapshot with a new ``generated_at``, so it naturally gets a new
        cache entry instead of silently serving a stale one. No cache
        eviction: orphaned entries from old snapshots are harmless disk
        usage, not a correctness problem, and were not asked for.
        """
        assert self._cache_dir is not None  # nosec B101 — _cache_path is only called when cache_dir is set (see render()); documents the precondition, never a user-controlled check
        raw_key = f"{report.assessment_id}:{report.generated_at.isoformat()}:{fmt}"
        digest = hashlib.sha256(raw_key.encode("utf-8")).hexdigest()[:16]
        return self._cache_dir / f"{report.assessment_id}-{digest}.{fmt}"
