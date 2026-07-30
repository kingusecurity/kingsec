"""API routes for job queue management — retry, cancel, list, metrics."""

from __future__ import annotations

from typing import TYPE_CHECKING, Any, cast

from fastapi import APIRouter, Depends, HTTPException, Request, status

from kingsec.application.distributed.ports import JobQueueRepositoryPort
from kingsec.application.distributed.retry_manager import DeadLetterService, RetryManager

from .auth import CurrentUser, get_current_user
from .dependencies import get_application

if TYPE_CHECKING:
    from kingsec.bootstrap.application import Application

router = APIRouter(prefix="/api/v1/queue", tags=["distributed_queue"])


def _get_queue_repo(request: Request) -> JobQueueRepositoryPort:
    app: Application = get_application(request)
    return cast(JobQueueRepositoryPort, app.resolve(JobQueueRepositoryPort))


def _get_retry_manager(request: Request) -> RetryManager:
    app: Application = get_application(request)
    return cast(RetryManager, app.resolve(RetryManager))


def _get_dead_letter_service(request: Request) -> DeadLetterService:
    app: Application = get_application(request)
    return cast(DeadLetterService, app.resolve(DeadLetterService))


@router.get("")
async def list_queue(
    request: Request,
    state: str | None = None,
    user: CurrentUser = Depends(get_current_user),
) -> dict[str, Any]:
    repo = _get_queue_repo(request)
    if state:
        entries = repo.find_by_state(state)
    else:
        entries = repo.find_all()
    return {
        "entries": [
            {
                "entry_id": e.entry_id,
                "job_id": e.job_id,
                "state": e.state.value,
                "target": e.target,
                "assigned_worker_id": e.assigned_worker_id,
                "retry_count": e.retry_count,
                "max_retries": e.max_retries,
                "error_message": e.error_message,
                "created_at": e.created_at,
                "updated_at": e.updated_at,
                "started_at": e.started_at,
                "completed_at": e.completed_at,
            }
            for e in entries
        ],
        "total": len(entries),
    }


@router.get("/metrics")
async def queue_metrics(
    request: Request,
    user: CurrentUser = Depends(get_current_user),
) -> dict[str, Any]:
    repo = _get_queue_repo(request)
    m = repo.get_metrics()
    return {
        "total_queued": m.total_queued,
        "total_assigned": m.total_assigned,
        "total_running": m.total_running,
        "total_completed": m.total_completed,
        "total_failed": m.total_failed,
        "total_cancelled": m.total_cancelled,
        "total_retrying": m.total_retrying,
        "total_expired": m.total_expired,
        "total_dead_letter": m.total_dead_letter,
        "average_wait_seconds": m.average_wait_seconds,
        "oldest_job_age_seconds": m.oldest_job_age_seconds,
    }


@router.post("/retry/{entry_id}")
async def retry_job(
    entry_id: str,
    request: Request,
    user: CurrentUser = Depends(get_current_user),
) -> dict[str, Any]:
    mgr = _get_retry_manager(request)
    try:
        entry = mgr.retry_job(entry_id)
    except ValueError as exc:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=str(exc)) from exc
    return {
        "message": f"Job '{entry_id}' queued for retry",
        "entry": {
            "entry_id": entry.entry_id,
            "state": entry.state.value,
            "retry_count": entry.retry_count,
        },
    }


@router.post("/cancel/{entry_id}")
async def cancel_job(
    entry_id: str,
    request: Request,
    user: CurrentUser = Depends(get_current_user),
) -> dict[str, Any]:
    mgr = _get_retry_manager(request)
    try:
        entry = mgr.cancel_job(entry_id)
    except ValueError as exc:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=str(exc)) from exc
    return {
        "message": f"Job '{entry_id}' cancelled",
        "entry": {
            "entry_id": entry.entry_id,
            "state": entry.state.value,
        },
    }


@router.get("/dead-letter")
async def list_dead_letter(
    request: Request,
    user: CurrentUser = Depends(get_current_user),
) -> dict[str, Any]:
    svc = _get_dead_letter_service(request)
    entries = svc.list()
    return {
        "entries": [
            {
                "entry_id": e.entry_id,
                "original_job_id": e.original_job_id,
                "original_entry_id": e.original_entry_id,
                "reason": e.reason,
                "retry_count": e.retry_count,
                "failed_at": e.failed_at,
            }
            for e in entries
        ],
        "total": len(entries),
    }


@router.post("/dead-letter/{entry_id}/requeue")
async def requeue_dead_letter(
    entry_id: str,
    request: Request,
    user: CurrentUser = Depends(get_current_user),
) -> dict[str, Any]:
    svc = _get_dead_letter_service(request)
    try:
        entry = svc.requeue(entry_id)
    except ValueError as exc:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=str(exc)) from exc
    return {
        "message": f"Dead letter entry '{entry_id}' requeued",
        "entry": {
            "entry_id": entry.entry_id,
            "state": entry.state.value,
        },
    }


@router.get("/{entry_id}")
async def get_queue_entry(
    entry_id: str,
    request: Request,
    user: CurrentUser = Depends(get_current_user),
) -> dict[str, Any]:
    repo = _get_queue_repo(request)
    entry = repo.get(entry_id)
    if not entry:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=f"Queue entry '{entry_id}' not found")
    return {
        "entry_id": entry.entry_id,
        "job_id": entry.job_id,
        "state": entry.state.value,
        "payload": entry.payload,
        "target": entry.target,
        "scanner_ids": list(entry.scanner_ids),
        "assigned_worker_id": entry.assigned_worker_id,
        "retry_count": entry.retry_count,
        "max_retries": entry.max_retries,
        "error_message": entry.error_message,
        "created_at": entry.created_at,
        "updated_at": entry.updated_at,
        "started_at": entry.started_at,
        "completed_at": entry.completed_at,
    }
