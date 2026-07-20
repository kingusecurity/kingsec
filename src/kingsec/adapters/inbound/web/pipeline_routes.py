from __future__ import annotations

from fastapi import APIRouter, Depends, HTTPException, Request, status

from kingsec.application.errors import PipelineNotFoundError, PipelineStateConflictError
from kingsec.application.ports.pipeline_service import PipelineServicePort
from kingsec.bootstrap.application import Application
from kingsec.domain import Role

from .auth import CurrentUser, get_current_user
from .dependencies import get_application

router = APIRouter(prefix="/api/v1/pipelines", tags=["pipelines"])

ADMIN_ONLY = Role.ADMIN


def _get_service(request: Request) -> PipelineServicePort:
    app: Application = get_application(request)
    return app.resolve(PipelineServicePort)


def _require_admin(user: CurrentUser) -> None:
    if user.role != ADMIN_ONLY:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Admin access required")


def _to_response(execution) -> dict:
    return {
        "pipeline_id": execution.pipeline_id.value,
        "target": execution.target,
        "state": execution.state.value,
        "stages": [
            {
                "name": s.name,
                "status": s.status,
                "started_at": s.started_at,
                "completed_at": s.completed_at,
                "error_message": s.error_message,
            }
            for s in execution.stages
        ],
        "job_id": execution.result.job_id,
        "queue_entry_id": execution.result.queue_entry_id,
        "agent_id": execution.result.agent_id,
        "report_id": execution.result.report_id,
        "notification_ids": list(execution.result.notification_ids),
        "findings_count": execution.result.findings_count,
        "summary": execution.result.summary,
        "error_message": execution.result.error_message,
        "owner_user_id": execution.owner_user_id,
        "scanner_ids": list(execution.scanner_ids),
        "priority": execution.priority,
        "created_at": execution.created_at,
        "updated_at": execution.updated_at,
    }


@router.post("/start")
async def start_pipeline(
    request: Request,
    body: dict,
    user: CurrentUser = Depends(get_current_user),
) -> dict:
    _require_admin(user)
    service = _get_service(request)
    try:
        execution = service.start_pipeline(
            target=body["target"],
            owner_user_id=body.get("owner_user_id", user.user_id),
            scanner_ids=body.get("scanner_ids"),
            priority=body.get("priority", "normal"),
        )
    except Exception as exc:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(exc)) from exc
    return {"message": "Pipeline started", "pipeline": _to_response(execution)}


@router.get("")
async def list_pipelines(
    request: Request,
    user: CurrentUser = Depends(get_current_user),
) -> dict:
    service = _get_service(request)
    executions = service.list_pipelines()
    return {"pipelines": [_to_response(e) for e in executions], "total": len(executions)}


@router.get("/{pipeline_id}")
async def get_pipeline(
    pipeline_id: str,
    request: Request,
    user: CurrentUser = Depends(get_current_user),
) -> dict:
    service = _get_service(request)
    try:
        execution = service.get_pipeline(pipeline_id)
    except PipelineNotFoundError as exc:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=str(exc)) from exc
    return _to_response(execution)


@router.post("/{pipeline_id}/cancel")
async def cancel_pipeline(
    pipeline_id: str,
    request: Request,
    user: CurrentUser = Depends(get_current_user),
) -> dict:
    _require_admin(user)
    service = _get_service(request)
    try:
        execution = service.cancel_pipeline(pipeline_id)
    except PipelineNotFoundError as exc:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=str(exc)) from exc
    except PipelineStateConflictError as exc:
        raise HTTPException(status_code=status.HTTP_409_CONFLICT, detail=str(exc)) from exc
    return {"message": f"Pipeline '{pipeline_id}' cancelled", "pipeline": _to_response(execution)}


@router.post("/{pipeline_id}/retry")
async def retry_pipeline(
    pipeline_id: str,
    request: Request,
    user: CurrentUser = Depends(get_current_user),
) -> dict:
    _require_admin(user)
    service = _get_service(request)
    try:
        execution = service.retry_pipeline(pipeline_id)
    except PipelineNotFoundError as exc:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=str(exc)) from exc
    except PipelineStateConflictError as exc:
        raise HTTPException(status_code=status.HTTP_409_CONFLICT, detail=str(exc)) from exc
    return {"message": f"Pipeline '{pipeline_id}' retried", "pipeline": _to_response(execution)}


@router.post("/{pipeline_id}/resume")
async def resume_pipeline(
    pipeline_id: str,
    request: Request,
    user: CurrentUser = Depends(get_current_user),
) -> dict:
    _require_admin(user)
    service = _get_service(request)
    try:
        execution = service.resume_pipeline(pipeline_id)
    except PipelineNotFoundError as exc:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=str(exc)) from exc
    return {"message": f"Pipeline '{pipeline_id}' resumed", "pipeline": _to_response(execution)}


@router.post("/{pipeline_id}/pause")
async def pause_pipeline(
    pipeline_id: str,
    request: Request,
    user: CurrentUser = Depends(get_current_user),
) -> dict:
    _require_admin(user)
    service = _get_service(request)
    try:
        execution = service.pause_pipeline(pipeline_id)
    except PipelineNotFoundError as exc:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=str(exc)) from exc
    return {"message": f"Pipeline '{pipeline_id}' paused", "pipeline": _to_response(execution)}
