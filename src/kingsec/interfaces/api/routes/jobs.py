from __future__ import annotations

from typing import Annotated

from fastapi import APIRouter, Body, HTTPException, status

from kingsec.application.errors import IllegalJobTransitionError, JobNotFoundError
from kingsec.application.ports.job_service import JobServicePort


def create_jobs_router(job_service: JobServicePort) -> APIRouter:
    """Create an ``APIRouter`` with scan-job endpoints."""
    router = APIRouter(prefix="/jobs", tags=["jobs"])

    # ── POST /jobs ───────────────────────────────────────────────────

    @router.post("", status_code=status.HTTP_202_ACCEPTED)
    async def create_job(body: Annotated[dict, Body()]) -> dict:
        """Submit a scan target for asynchronous assessment."""
        raw_target = body.get("target")
        if not raw_target or not isinstance(raw_target, str) or not raw_target.strip():
            raise HTTPException(
                status_code=status.HTTP_422_UNPROCESSABLE_CONTENT,
                detail="target must be a non-empty string",
            )
        config = body.get("config")
        if config is not None and not isinstance(config, dict):
            raise HTTPException(
                status_code=status.HTTP_422_UNPROCESSABLE_CONTENT,
                detail="config must be an object",
            )
        job = job_service.submit_scan(target=raw_target.strip(), config=config)
        return _job_to_response(job)

    # ── GET /jobs ─────────────────────────────────────────────────────

    @router.get("")
    async def list_jobs() -> list[dict]:
        """Return every known scan job, newest first."""
        jobs = job_service.list_jobs()
        return [_job_to_response(j) for j in jobs]

    # ── GET /jobs/{job_id} ────────────────────────────────────────────

    @router.get("/{job_id}")
    async def get_job(job_id: str) -> dict:
        """Return details for a single scan job."""
        try:
            job = job_service.get_job(job_id)
        except JobNotFoundError:
            raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Job not found") from None
        return _job_to_response(job)

    # ── DELETE /jobs/{job_id} ─────────────────────────────────────────

    @router.delete("/{job_id}")
    async def cancel_job(job_id: str) -> dict:
        """Cancel a pending or running scan job."""
        try:
            job = job_service.cancel_job(job_id)
        except JobNotFoundError:
            raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Job not found") from None
        except IllegalJobTransitionError:
            raise HTTPException(
                status_code=status.HTTP_409_CONFLICT,
                detail="Job is already in a terminal state and cannot be cancelled",
            ) from None
        return _job_to_response(job)

    # ── GET /jobs/{job_id}/result ─────────────────────────────────────

    @router.get("/{job_id}/result")
    async def get_job_result(job_id: str) -> dict:
        """Return findings for a completed scan job."""
        try:
            result = job_service.get_job_result(job_id)
        except JobNotFoundError:
            raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Job not found") from None
        except IllegalJobTransitionError:
            raise HTTPException(
                status_code=status.HTTP_409_CONFLICT,
                detail="Job has not completed yet",
            ) from None
        return {
            "job_id": result.job_id,
            "findings": list(result.findings),
            "completed_at": result.completed_at.isoformat(),
            "error": result.error,
        }

    return router


# -----------------------------------------------------------------------
# Helpers
# -----------------------------------------------------------------------


def _job_to_response(job: object) -> dict:
    """Convert a ``ScanJob`` to a plain JSON-safe dict."""
    return {
        "job_id": job.id.value,  # type: ignore[union-attr]
        "status": job.status.value,  # type: ignore[union-attr]
        "target": job.target,  # type: ignore[union-attr]
        "config": job.config,  # type: ignore[union-attr]
        "created_at": job.created_at.isoformat(),  # type: ignore[union-attr]
        "updated_at": job.updated_at.isoformat(),  # type: ignore[union-attr]
    }
