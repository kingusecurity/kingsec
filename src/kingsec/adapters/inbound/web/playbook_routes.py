from __future__ import annotations

from typing import TYPE_CHECKING, Any

from fastapi import APIRouter, Depends, HTTPException, Query, Request

from .auth import CurrentUser, get_current_user
from .dependencies import get_application

if TYPE_CHECKING:
    from kingsec.application.playbooks.service import PlaybookService
    from kingsec.bootstrap.application import Application

router = APIRouter(prefix="/api/v1", tags=["Playbooks"])


def _get_service(request: Request, _: CurrentUser = Depends(get_current_user)) -> Any:
    from kingsec.application.playbooks.service import PlaybookService
    app: Application = get_application(request)
    return app.resolve(PlaybookService)


@router.get("/playbooks")
def list_playbooks(
    enabled: bool | None = Query(None),
    category: str | None = Query(None),
    trigger_type: str | None = Query(None),
    severity: str | None = Query(None),
    service: PlaybookService = Depends(_get_service),
) -> dict[str, Any]:
    playbooks = service.list_playbooks(enabled, category, trigger_type, severity)
    return {
        "items": [_playbook_to_dict(p) for p in playbooks],
        "total": len(playbooks),
    }


@router.post("/playbooks", status_code=201)
def create_playbook(
    body: dict[str, Any],
    service: PlaybookService = Depends(_get_service),
) -> dict[str, Any]:
    try:
        pb = service.create_playbook(
            name=body["name"],
            description=body.get("description", ""),
            category=body.get("category", "general"),
            severity=body.get("severity", "medium"),
            tags=body.get("tags"),
            trigger=body.get("trigger"),
            actions=body.get("actions"),
            rollback_actions=body.get("rollback_actions"),
        )
        return _playbook_to_dict(pb)
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc


@router.get("/playbooks/history")
def list_executions(
    status: str | None = Query(None),
    trigger_type: str | None = Query(None),
    limit: int = Query(50, ge=1, le=200),
    offset: int = Query(0, ge=0),
    service: PlaybookService = Depends(_get_service),
) -> dict[str, Any]:
    items = service.list_executions(status, trigger_type, limit, offset)
    return {
        "items": [_execution_to_dict(e) for e in items],
        "total": len(items),
        "limit": limit,
        "offset": offset,
    }


@router.get("/playbooks/history/{execution_id}")
def get_execution(
    execution_id: str,
    service: PlaybookService = Depends(_get_service),
) -> dict[str, Any]:
    result = service.get_execution(execution_id)
    if not result:
        raise HTTPException(status_code=404, detail="Execution not found")
    return _execution_to_dict(result)


@router.get("/playbooks/stats")
def playbook_stats(
    service: PlaybookService = Depends(_get_service),
) -> dict[str, Any]:
    return {
        "playbook_count": service.get_playbook_count(),
        **service.get_history_stats(),
    }


@router.get("/playbooks/{playbook_id}")
def get_playbook(
    playbook_id: str,
    service: PlaybookService = Depends(_get_service),
) -> dict[str, Any]:
    pb = service.get_playbook(playbook_id)
    if not pb:
        raise HTTPException(status_code=404, detail="Playbook not found")
    return _playbook_to_dict(pb)


@router.put("/playbooks/{playbook_id}")
def update_playbook(
    playbook_id: str,
    body: dict[str, Any],
    service: PlaybookService = Depends(_get_service),
) -> dict[str, Any]:
    try:
        pb = service.update_playbook(
            playbook_id=playbook_id,
            name=body.get("name"),
            description=body.get("description"),
            category=body.get("category"),
            severity=body.get("severity"),
            tags=body.get("tags"),
            enabled=body.get("enabled"),
            trigger=body.get("trigger"),
            actions=body.get("actions"),
            rollback_actions=body.get("rollback_actions"),
        )
        return _playbook_to_dict(pb)
    except ValueError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc


@router.delete("/playbooks/{playbook_id}", status_code=204)
def delete_playbook(
    playbook_id: str,
    service: PlaybookService = Depends(_get_service),
) -> None:
    service.delete_playbook(playbook_id)


@router.post("/playbooks/{playbook_id}/execute")
def execute_playbook(
    playbook_id: str,
    body: dict[str, Any] | None = None,
    service: PlaybookService = Depends(_get_service),
) -> dict[str, Any]:
    try:
        result = service.execute_playbook(
            playbook_id=playbook_id,
            trigger_entity_id=(body or {}).get("trigger_entity_id", ""),
            context=(body or {}).get("context"),
        )
        return _execution_to_dict(result)
    except ValueError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc


@router.post("/playbooks/{playbook_id}/enable")
def enable_playbook(
    playbook_id: str,
    service: PlaybookService = Depends(_get_service),
) -> dict[str, Any]:
    try:
        pb = service.enable_playbook(playbook_id)
        return _playbook_to_dict(pb)
    except ValueError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc


@router.post("/playbooks/{playbook_id}/disable")
def disable_playbook(
    playbook_id: str,
    service: PlaybookService = Depends(_get_service),
) -> dict[str, Any]:
    try:
        pb = service.disable_playbook(playbook_id)
        return _playbook_to_dict(pb)
    except ValueError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc


def _playbook_to_dict(pb: Any) -> dict[str, Any]:
    return {
        "id": pb.id,
        "name": pb.name,
        "description": pb.description,
        "category": pb.category,
        "severity": pb.severity,
        "tags": list(pb.tags),
        "enabled": pb.enabled,
        "trigger": {
            "trigger_type": pb.trigger.trigger_type.value,
            "config": pb.trigger.config,
            "conditions": pb.trigger.conditions,
        },
        "actions": [
            {
                "action_type": a.action_type.value,
                "config": a.config,
                "order": a.order,
                "timeout_seconds": a.timeout_seconds,
                "retry_count": a.retry_count,
                "continue_on_failure": a.continue_on_failure,
            }
            for a in pb.actions
        ],
        "rollback_actions": [
            {
                "action_type": a.action_type.value,
                "config": a.config,
                "order": a.order,
                "timeout_seconds": a.timeout_seconds,
                "retry_count": a.retry_count,
                "continue_on_failure": a.continue_on_failure,
            }
            for a in pb.rollback_actions
        ],
        "created_at": pb.created_at,
        "updated_at": pb.updated_at,
    }


def _execution_to_dict(e: Any) -> dict[str, Any]:
    return {
        "id": e.id,
        "playbook_id": e.playbook_id,
        "playbook_name": e.playbook_name,
        "trigger_type": e.trigger_type,
        "trigger_entity_id": e.trigger_entity_id,
        "status": e.status.value,
        "action_logs": [
            {
                "action_type": l.action_type,
                "status": l.status,
                "started_at": l.started_at,
                "completed_at": l.completed_at,
                "duration_ms": l.duration_ms,
                "output": l.output,
                "error": l.error,
                "retry_attempts": l.retry_attempts,
            }
            for l in e.action_logs
        ],
        "started_at": e.started_at,
        "completed_at": e.completed_at,
        "duration_ms": e.duration_ms,
        "error": e.error,
        "rolled_back": e.rolled_back,
        "created_at": e.created_at,
    }
