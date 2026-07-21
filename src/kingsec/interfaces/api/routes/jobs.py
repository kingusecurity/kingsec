from __future__ import annotations

from collections.abc import Callable
from typing import Annotated

from fastapi import APIRouter, Body, Depends, HTTPException, status

from kingsec.application.errors import IllegalJobTransitionError, JobNotFoundError
from kingsec.application.ports.job_service import JobServicePort


def create_jobs_router(
    job_service: JobServicePort,
    *,
    get_current_user: Callable | None = None,
) -> APIRouter:
    """Create an ``APIRouter`` with scan-job endpoints.

    All endpoints require authentication via *get_current_user*.
    """
    router = APIRouter(prefix="/jobs", tags=["jobs"])

    show_401_403 = {
        401: {"description": "Missing or invalid token"},
        403: {"description": "Insufficient permissions"},
    }

    @router.post(
        "",
        status_code=status.HTTP_202_ACCEPTED,
        responses={
            202: {"description": "Job created"},
            **show_401_403,
        },
    )
    async def create_job(
        body: Annotated[dict, Body()],
        _user=Depends(get_current_user),
    ) -> dict:
        """Submit a scan target for asynchronous assessment.  Requires ANALYST or ADMIN."""
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

    @router.get(
        "",
        responses={200: {"description": "List of jobs"}, **show_401_403},
    )
    async def list_jobs(
        _user=Depends(get_current_user),
    ) -> list[dict]:
        """Return every known scan job, newest first.  Requires ANALYST or ADMIN."""
        jobs = job_service.list_jobs()
        return [_job_to_response(j) for j in jobs]

    @router.get(
        "/{job_id}",
        responses={200: {"description": "Job details"}, **show_401_403},
    )
    async def get_job(
        job_id: str,
        _user=Depends(get_current_user),
    ) -> dict:
        """Return details for a single scan job.  Requires ANALYST or ADMIN."""
        try:
            job = job_service.get_job(job_id)
        except JobNotFoundError:
            raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Job not found") from None
        return _job_to_response(job)

    @router.delete(
        "/{job_id}",
        responses={
            200: {"description": "Job cancelled"},
            **show_401_403,
            409: {"description": "Job is in a terminal state"},
        },
    )
    async def cancel_job(
        job_id: str,
        _user=Depends(get_current_user),
    ) -> dict:
        """Cancel a pending or running scan job.  Requires ANALYST or ADMIN."""
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

    @router.get(
        "/{job_id}/result",
        responses={
            200: {"description": "Job result"},
            **show_401_403,
            409: {"description": "Job not yet completed"},
        },
    )
    async def get_job_result(
        job_id: str,
        _user=Depends(get_current_user),
    ) -> dict:
        """Return findings for a completed scan job.  Requires ANALYST or ADMIN."""
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
