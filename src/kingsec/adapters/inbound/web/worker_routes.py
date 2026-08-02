"""API routes for worker registration, heartbeat, and lifecycle."""

from __future__ import annotations

from typing import TYPE_CHECKING, Any, cast

from fastapi import APIRouter, Depends, HTTPException, Request, status

from kingsec.application.distributed.worker_service import HeartbeatManager, WorkerRegistrationService
from kingsec.application.errors import WorkerNotFoundError

from .auth import CurrentUser, get_current_user
from .dependencies import get_application

if TYPE_CHECKING:
    from kingsec.bootstrap.application import Application

router = APIRouter(prefix="/api/v1/workers", tags=["workers"])


def _get_registration_service(request: Request) -> WorkerRegistrationService:
    app: Application = get_application(request)
    return cast(WorkerRegistrationService, app.resolve(WorkerRegistrationService))


def _get_heartbeat_manager(request: Request) -> HeartbeatManager:
    app: Application = get_application(request)
    return cast(HeartbeatManager, app.resolve(HeartbeatManager))


@router.post("/register")
async def register_worker(
    request: Request,
    body: dict[str, Any],
    user: CurrentUser = Depends(get_current_user),
) -> dict[str, Any]:
    service = _get_registration_service(request)
    try:
        worker = service.register(
            worker_id=body["worker_id"],
            hostname=body.get("hostname", ""),
            os=body.get("os", ""),
            cpu=body.get("cpu", ""),
            ram_mb=body.get("ram_mb", 0),
            capabilities=body.get("capabilities"),
        )
    except (KeyError, TypeError) as exc:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="worker_id is required, and each capability must be an object with a scanner_id",
        ) from exc
    return {
        "message": "Worker registered",
        "worker": {
            "worker_id": worker.worker_id,
            "hostname": worker.hostname,
            "status": worker.status.value,
            "health": worker.health,
            "last_heartbeat": worker.last_heartbeat,
        },
    }


@router.post("/heartbeat")
async def worker_heartbeat(
    request: Request,
    body: dict[str, Any],
    user: CurrentUser = Depends(get_current_user),
) -> dict[str, Any]:
    mgr = _get_heartbeat_manager(request)
    try:
        worker = mgr.process_heartbeat(
            worker_id=body["worker_id"],
            status=body.get("status", "online"),
            current_jobs=body.get("current_jobs"),
            health=body.get("health", "healthy"),
        )
    except WorkerNotFoundError as exc:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=str(exc)) from exc
    return {
        "message": "Heartbeat received",
        "worker": {
            "worker_id": worker.worker_id,
            "status": worker.status.value,
            "health": worker.health,
            "last_heartbeat": worker.last_heartbeat,
        },
    }


@router.get("")
async def list_workers(
    request: Request,
    user: CurrentUser = Depends(get_current_user),
) -> dict[str, Any]:
    service = _get_registration_service(request)
    workers = service.list_all()
    return {
        "workers": [
            {
                "worker_id": w.worker_id,
                "hostname": w.hostname,
                "os": w.os,
                "cpu": w.cpu,
                "ram_mb": w.ram_mb,
                "status": w.status.value,
                "health": w.health,
                "last_heartbeat": w.last_heartbeat,
                "current_jobs": list(w.current_jobs),
                "capabilities": [
                    {"scanner_id": c.scanner_id, "scanner_name": c.scanner_name, "scanner_version": c.scanner_version}
                    for c in w.capabilities
                ],
                "created_at": w.created_at,
            }
            for w in workers
        ],
        "total": len(workers),
    }


@router.get("/{worker_id}")
async def get_worker(
    worker_id: str,
    request: Request,
    user: CurrentUser = Depends(get_current_user),
) -> dict[str, Any]:
    service = _get_registration_service(request)
    try:
        w = service.get(worker_id)
    except WorkerNotFoundError as exc:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=str(exc)) from exc
    return {
        "worker": {
            "worker_id": w.worker_id,
            "hostname": w.hostname,
            "os": w.os,
            "cpu": w.cpu,
            "ram_mb": w.ram_mb,
            "status": w.status.value,
            "health": w.health,
            "last_heartbeat": w.last_heartbeat,
            "current_jobs": list(w.current_jobs),
            "capabilities": [
                {"scanner_id": c.scanner_id, "scanner_name": c.scanner_name, "scanner_version": c.scanner_version}
                for c in w.capabilities
            ],
            "created_at": w.created_at,
            "updated_at": w.updated_at,
        }
    }


@router.delete("/{worker_id}")
async def delete_worker(
    worker_id: str,
    request: Request,
    user: CurrentUser = Depends(get_current_user),
) -> dict[str, Any]:
    service = _get_registration_service(request)
    try:
        service.delete(worker_id)
    except WorkerNotFoundError as exc:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=str(exc)) from exc
    return {"message": f"Worker '{worker_id}' deleted"}
