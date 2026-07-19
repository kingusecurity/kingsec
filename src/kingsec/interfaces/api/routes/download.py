"""Report download REST routes.

The API only:
    • validates the request
    • obtains the report through the service port
    • returns the rendered content with correct headers

Business logic remains inside the Application Layer.
"""

from __future__ import annotations

from fastapi import APIRouter, HTTPException, status
from fastapi.responses import Response

from kingsec.application import ReportServicePort

# Maps format names → (media_type, file_extension)
_FORMAT_MAP: dict[str, tuple[str, str]] = {
    "markdown": ("text/markdown", ".md"),
    "html": ("text/html", ".html"),
    "pdf": ("application/pdf", ".pdf"),
    "json": ("application/json", ".json"),
    "csv": ("text/csv", ".csv"),
    "sarif": ("application/sarif+json", ".sarif"),
}

_SUPPORTED_FORMATS = frozenset(_FORMAT_MAP)


# ---------------------------------------------------------------------------
# Router factory
# ---------------------------------------------------------------------------


def create_download_router(service: ReportServicePort) -> APIRouter:
    """Create an ``APIRouter`` with report download endpoints."""
    router = APIRouter(prefix="/report", tags=["download"])

    @router.get("/{report_id}/download/{format_name}")
    async def download_report(report_id: str, format_name: str) -> Response:
        """Download a report in the specified format."""
        if format_name not in _SUPPORTED_FORMATS:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail=f"Unsupported format: {format_name}",
            )

        try:
            rendered = service.render_report(report_id, format_name)
        except Exception:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail=f"Report not found: {report_id}",
            ) from None

        media_type, ext = _FORMAT_MAP[format_name]
        return Response(
            content=rendered.content,
            media_type=media_type,
            headers={
                "Content-Disposition": f'attachment; filename="report{ext}"',
            },
        )

    return router
