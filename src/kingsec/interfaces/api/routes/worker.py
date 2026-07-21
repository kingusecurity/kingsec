from __future__ import annotations

from collections.abc import Callable
from typing import Any

from fastapi import APIRouter, Depends, HTTPException, status

from kingsec.application.ports.outbound import WorkerServicePort


def create_worker_router(
    worker_service: WorkerServicePort,
    *,
    get_current_user: Callable[..., Any] | None = None,
) -> APIRouter:
    """Create an ``APIRouter`` with worker control endpoints.

    All endpoints require authentication via *get_current_user*.
    """
    router = APIRouter(prefix="/worker", tags=["worker"])

    @router.post("/start", dependencies=[Depends(get_current_user)])
    async def start_worker() -> dict[str, Any]:
        worker_service.start_worker()
        return {"status": "worker_started"}

    @router.post("/stop", dependencies=[Depends(get_current_user)])
    async def stop_worker() -> dict[str, Any]:
        worker_service.stop_worker()
        return {"status": "worker_stopped"}

    @router.post("/execute", dependencies=[Depends(get_current_user)])
    async def execute_job() -> dict[str, Any]:
        job_id = worker_service.execute_next_job()
        if job_id is None:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail="No pending jobs to execute",
            )
        return {"job_id": job_id}

    @router.get("/status", dependencies=[Depends(get_current_user)])
    async def get_status() -> dict[str, Any]:
        return {"status": worker_service.status().value}

    @router.get("/heartbeat", dependencies=[Depends(get_current_user)])
    async def get_heartbeat() -> dict[str, Any]:
        hb = worker_service.heartbeat()
        return {
            "worker_id": str(hb.worker_id),
            "status": hb.status.value,
            "timestamp": hb.timestamp,
            "current_job_id": hb.current_job_id,
            "jobs_completed": hb.jobs_completed,
            "jobs_failed": hb.jobs_failed,
        }

    return router
