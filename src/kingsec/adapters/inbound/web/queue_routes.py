from __future__ import annotations

from fastapi import APIRouter, Depends, HTTPException, Request, status

from kingsec.application.errors import QueueEntryNotFoundError
from kingsec.application.ports.queue_service import QueueServicePort
from kingsec.bootstrap.application import Application
from kingsec.domain import Role

from .auth import CurrentUser, get_current_user
from .dependencies import get_application

router = APIRouter(prefix="/api/v1/queue", tags=["queue"])

ADMIN_ONLY = Role.ADMIN


def _get_service(request: Request) -> QueueServicePort:
    app: Application = get_application(request)
    return app.resolve(QueueServicePort)


def _require_admin(user: CurrentUser) -> None:
    if user.role != ADMIN_ONLY:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Admin access required")


@router.post("/entry")
async def enqueue(
    request: Request,
    body: dict,
    user: CurrentUser = Depends(get_current_user),
) -> dict:
    _require_admin(user)
    service = _get_service(request)
    try:
        entry = service.enqueue(
            payload=body["payload"],
            target=body["target"],
            priority=body.get("priority", "normal"),
            scanner_ids=body.get("scanner_ids"),
            owner_user_id=body.get("owner_user_id", user.user_id),
            estimated_duration_seconds=body.get("estimated_duration_seconds", 300),
        )
    except Exception as exc:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(exc)) from exc
    return {
        "message": "Job enqueued",
        "entry": {
            "entry_id": entry.entry_id,
            "job_id": entry.job_id,
            "priority": entry.priority.name.lower(),
            "state": entry.state.value,
            "target": entry.target,
        },
    }


@router.get("/entry/{entry_id}")
async def get_entry(
    entry_id: str,
    request: Request,
    user: CurrentUser = Depends(get_current_user),
) -> dict:
    _require_admin(user)
    service = _get_service(request)
    try:
        entry = service.dequeue(entry_id)
    except QueueEntryNotFoundError as exc:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=str(exc)) from exc
    return {
        "entry_id": entry.entry_id,
        "job_id": entry.job_id,
        "priority": entry.priority.name.lower(),
        "state": entry.state.value,
        "target": entry.target,
        "payload": entry.payload,
        "owner_user_id": entry.owner_user_id,
        "assigned_agent_id": entry.assigned_agent_id,
        "retry_count": entry.retry_count,
        "created_at": entry.created_at,
        "updated_at": entry.updated_at,
        "position": entry.position,
    }


@router.post("/entry/{entry_id}/cancel")
async def cancel_entry(
    entry_id: str,
    request: Request,
    user: CurrentUser = Depends(get_current_user),
) -> dict:
    _require_admin(user)
    service = _get_service(request)
    try:
        service.cancel(entry_id)
    except QueueEntryNotFoundError as exc:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=str(exc)) from exc
    return {"message": f"Queue entry '{entry_id}' cancelled"}


@router.post("/entry/{entry_id}/priority")
async def change_priority(
    entry_id: str,
    request: Request,
    body: dict,
    user: CurrentUser = Depends(get_current_user),
) -> dict:
    _require_admin(user)
    service = _get_service(request)
    try:
        entry = service.change_priority(entry_id, body.get("priority", "normal"))
    except QueueEntryNotFoundError as exc:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=str(exc)) from exc
    return {
        "message": f"Priority changed to {entry.priority.name.lower()}",
        "entry_id": entry.entry_id,
        "priority": entry.priority.name.lower(),
    }


@router.post("/entry/{entry_id}/move")
async def move_entry(
    entry_id: str,
    request: Request,
    body: dict,
    user: CurrentUser = Depends(get_current_user),
) -> dict:
    _require_admin(user)
    service = _get_service(request)
    try:
        entry = service.move_position(entry_id, body.get("new_position", 0))
    except QueueEntryNotFoundError as exc:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=str(exc)) from exc
    return {
        "message": f"Entry moved to position {entry.position}",
        "entry_id": entry.entry_id,
        "position": entry.position,
    }


@router.post("/entry/{entry_id}/assign")
async def assign_agent(
    entry_id: str,
    request: Request,
    user: CurrentUser = Depends(get_current_user),
) -> dict:
    _require_admin(user)
    service = _get_service(request)
    try:
        agent_id = service.assign_best_agent(entry_id)
    except QueueEntryNotFoundError as exc:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=str(exc)) from exc
    if agent_id:
        return {"message": f"Agent '{agent_id}' assigned", "agent_id": agent_id}
    return {"message": "No suitable agent available", "agent_id": None}


@router.get("/entries")
async def list_queue(
    request: Request,
    user: CurrentUser = Depends(get_current_user),
) -> dict:
    service = _get_service(request)
    entries = service.list_queue()
    return {
        "entries": [
            {
                "entry_id": e.entry_id,
                "job_id": e.job_id,
                "priority": e.priority.name.lower(),
                "state": e.state.value,
                "target": e.target,
                "owner_user_id": e.owner_user_id,
                "assigned_agent_id": e.assigned_agent_id,
                "retry_count": e.retry_count,
                "created_at": e.created_at,
                "position": e.position,
            }
            for e in entries
        ],
        "total": len(entries),
    }


@router.get("/statistics")
async def get_statistics(
    request: Request,
    user: CurrentUser = Depends(get_current_user),
) -> dict:
    service = _get_service(request)
    stats = service.get_statistics()
    return {
        "total_entries": stats.total_entries,
        "waiting": stats.waiting,
        "ready": stats.ready,
        "running": stats.running,
        "blocked": stats.blocked,
        "completed": stats.completed,
        "failed": stats.failed,
        "cancelled": stats.cancelled,
        "average_wait_time_seconds": stats.average_wait_time_seconds,
        "longest_wait_time_seconds": stats.longest_wait_time_seconds,
        "oldest_entry_age_seconds": stats.oldest_entry_age_seconds,
        "queue_full": stats.queue_full,
        "paused": stats.paused,
    }


@router.post("/pause")
async def pause_queue(
    request: Request,
    user: CurrentUser = Depends(get_current_user),
) -> dict:
    _require_admin(user)
    service = _get_service(request)
    service.pause()
    return {"message": "Queue paused"}


@router.post("/resume")
async def resume_queue(
    request: Request,
    user: CurrentUser = Depends(get_current_user),
) -> dict:
    _require_admin(user)
    service = _get_service(request)
    service.resume()
    return {"message": "Queue resumed"}


@router.get("/next")
async def get_next_job(
    request: Request,
    user: CurrentUser = Depends(get_current_user),
) -> dict:
    _require_admin(user)
    service = _get_service(request)
    entry = service.get_next()
    if not entry:
        return {"message": "No job available", "entry": None}
    return {
        "entry": {
            "entry_id": entry.entry_id,
            "job_id": entry.job_id,
            "priority": entry.priority.name.lower(),
            "state": entry.state.value,
            "target": entry.target,
            "payload": entry.payload,
            "assigned_agent_id": entry.assigned_agent_id,
        }
    }
