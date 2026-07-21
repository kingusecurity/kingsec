from __future__ import annotations

from collections.abc import Callable

from fastapi import APIRouter, Depends, HTTPException, status

from kingsec.application.ports.outbound import WorkerServicePort


def create_worker_router(
    worker_service: WorkerServicePort,
    *,
    get_current_user: Callable | None = None,
) -> APIRouter:
    """Create an ``APIRouter`` with worker control endpoints.

    All endpoints require authentication via *get_current_user*.
    """
    router = APIRouter(prefix="/worker", tags=["worker"])

    requires_auth = {"dependencies": [Depends(get_current_user)]}

    @router.post("/start", **requires_auth)
    async def start_worker() -> dict:
        worker_service.start_worker()
        return {"status": "worker_started"}

    @router.post("/stop", **requires_auth)
    async def stop_worker() -> dict:
        worker_service.stop_worker()
        return {"status": "worker_stopped"}

    @router.post("/execute", **requires_auth)
    async def execute_job() -> dict:
        job_id = worker_service.execute_next_job()
        if job_id is None:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail="No pending jobs to execute",
            )
        return {"job_id": job_id}

    @router.get("/status", **requires_auth)
    async def get_status() -> dict:
        return {"status": worker_service.status().value}

    @router.get("/heartbeat", **requires_auth)
    async def get_heartbeat() -> dict:
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
