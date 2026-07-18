"""Report generation & retrieval REST routes.

The API only:
    • validates HTTP requests
    • invokes the report service port
    • converts results into JSON responses

Business logic remains inside the Application Layer.
"""

from __future__ import annotations

from typing import Annotated

from fastapi import APIRouter, Body, HTTPException, status

from kingsec.application import ReportServicePort


# ---------------------------------------------------------------------------
# Router factory
# ---------------------------------------------------------------------------


def create_report_router(service: ReportServicePort) -> APIRouter:
    """Create an ``APIRouter`` with report endpoints wired to the given port."""

    router = APIRouter(prefix="/report", tags=["report"])

    # ── POST /report ─────────────────────────────────────────────────────

    @router.post("")
    async def generate_report(
        body: Annotated[dict, Body()],
    ) -> dict:
        """Generate a report for a completed scan."""
        raw_id = _extract_scan_id(body)
        result = service.generate_report(raw_id)
        return {
            "report_id": result.report_id,
            "status": result.status,
            "generated_at": result.generated_at.isoformat(),
            "finding_count": result.finding_count,
        }

    # ── GET /report/{report_id} ──────────────────────────────────────────

    @router.get("/{report_id}")
    async def get_report(report_id: str) -> dict:
        """Return the native JSON report."""
        if not report_id or not report_id.strip():
            raise HTTPException(
                status_code=status.HTTP_422_UNPROCESSABLE_CONTENT,
                detail="report_id must be a non-empty string",
            )
        try:
            return service.get_report(report_id.strip())
        except Exception:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail=f"Report not found: {report_id}",
            ) from None

    # ── GET /report/{report_id}/summary ──────────────────────────────────

    @router.get("/{report_id}/summary")
    async def get_summary(report_id: str) -> dict:
        """Return executive summary + risk summary."""
        if not report_id or not report_id.strip():
            raise HTTPException(
                status_code=status.HTTP_422_UNPROCESSABLE_CONTENT,
                detail="report_id must be a non-empty string",
            )
        try:
            return service.get_summary(report_id.strip())
        except Exception:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail=f"Report not found: {report_id}",
            ) from None

    # ── GET /report/{report_id}/formats ──────────────────────────────────

    @router.get("/{report_id}/formats")
    async def get_formats(report_id: str) -> list[str]:
        """Return available output formats."""
        if not report_id or not report_id.strip():
            raise HTTPException(
                status_code=status.HTTP_422_UNPROCESSABLE_CONTENT,
                detail="report_id must be a non-empty string",
            )
        try:
            return service.get_formats(report_id.strip())
        except Exception:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail=f"Report not found: {report_id}",
            ) from None

    return router


# ---------------------------------------------------------------------------
# Internal helpers
# ---------------------------------------------------------------------------


def _extract_scan_id(body: dict) -> str:
    """Extract and validate the scan_id from the request body."""
    raw = body.get("scan_id")
    if not raw or not isinstance(raw, str) or not raw.strip():
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_CONTENT,
            detail="scan_id must be a non-empty string",
        )
    return raw.strip()
