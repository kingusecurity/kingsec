from __future__ import annotations

from typing import TYPE_CHECKING, Any, cast

from fastapi import APIRouter, Depends, HTTPException, Request, status

from kingsec.application.ports.agent_service import AgentServicePort
from kingsec.domain import Role
from kingsec.domain.agent import (
    AgentArchitecture,
    AgentCapability,
    AgentHealth,
    AgentHeartbeat,
    AgentId,
    AgentPlatform,
    AgentRegistration,
    AgentState,
)

if TYPE_CHECKING:
    from kingsec.bootstrap.application import Application

from .auth import CurrentUser, get_current_user
from .dependencies import get_application

router = APIRouter(prefix="/api/v1/agents", tags=["agents"])

ADMIN_ONLY = Role.ADMIN


def _get_service(request: Request) -> AgentServicePort:
    app: Application = get_application(request)
    return cast(AgentServicePort, app.resolve(AgentServicePort))


def _require_admin(user: CurrentUser) -> None:
    if user.role != ADMIN_ONLY:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Admin access required")


@router.post("/register")
async def register_agent(
    request: Request,
    body: dict[str, Any],
    user: CurrentUser = Depends(get_current_user),
) -> dict[str, Any]:
    _require_admin(user)
    service = _get_service(request)
    try:
        reg = AgentRegistration(
            agent_id=AgentId(body["agent_id"]),
            name=body.get("name", body["agent_id"]),
            platform=AgentPlatform(body.get("platform", "linux")),
            architecture=AgentArchitecture(body.get("architecture", "amd64")),
            version=body.get("version", "1.0.0"),
            hostname=body.get("hostname", ""),
            capability=AgentCapability(
                max_concurrent_jobs=body.get("max_concurrent_jobs", 1),
                supported_scanners=tuple(body.get("supported_scanners", [])),
                max_memory_mb=body.get("max_memory_mb", 1024),
                max_disk_mb=body.get("max_disk_mb", 10240),
            ),
            api_key_hash=body.get("api_key_hash", ""),
        )
        agent = service.register(reg)
    except Exception as exc:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(exc)) from exc
    return {
        "message": f"Agent '{agent.id}' registered",
        "agent": {
            "id": agent.id.value,
            "name": agent.name,
            "state": agent.state.value,
            "platform": agent.platform.value,
            "architecture": agent.architecture.value,
        },
    }


@router.post("/heartbeat")
async def agent_heartbeat(
    request: Request,
    body: dict[str, Any],
    user: CurrentUser = Depends(get_current_user),
) -> dict[str, Any]:
    _require_admin(user)
    service = _get_service(request)
    try:
        hb = AgentHeartbeat(
            agent_id=AgentId(body["agent_id"]),
            state=AgentState(body.get("state", "online")),
            health=AgentHealth(
                cpu_usage_percent=body.get("cpu_usage", 0.0),
                memory_usage_percent=body.get("memory_usage", 0.0),
                disk_usage_percent=body.get("disk_usage", 0.0),
                uptime_seconds=body.get("uptime_seconds", 0),
                error_message=body.get("error_message", ""),
            ),
            current_job_id=body.get("current_job_id"),
            jobs_completed=body.get("jobs_completed", 0),
            jobs_failed=body.get("jobs_failed", 0),
        )
        service.handle_heartbeat(hb)
    except Exception as exc:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=str(exc)) from exc
    return {"message": "Heartbeat received"}


@router.get("")
async def list_agents(
    request: Request,
    user: CurrentUser = Depends(get_current_user),
) -> dict[str, Any]:
    service = _get_service(request)
    agents = service.list_agents()
    return {
        "agents": [
            {
                "id": a.id.value,
                "name": a.name,
                "state": a.state.value,
                "platform": a.platform.value,
                "architecture": a.architecture.value,
                "version": a.version,
                "hostname": a.hostname,
                "current_job_id": a.current_job_id,
                "last_heartbeat_at": a.last_heartbeat_at,
                "jobs_completed": a.statistics.total_jobs_completed,
                "jobs_failed": a.statistics.total_jobs_failed,
            }
            for a in agents
        ]
    }


@router.get("/{agent_id}")
async def get_agent(
    agent_id: str,
    request: Request,
    user: CurrentUser = Depends(get_current_user),
) -> dict[str, Any]:
    service = _get_service(request)
    agent = service.get_agent(agent_id)
    if not agent:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=f"Agent '{agent_id}' not found")
    return {
        "id": agent.id.value,
        "name": agent.name,
        "state": agent.state.value,
        "platform": agent.platform.value,
        "architecture": agent.architecture.value,
        "version": agent.version,
        "hostname": agent.hostname,
        "current_job_id": agent.current_job_id,
        "registered_at": agent.registered_at,
        "last_heartbeat_at": agent.last_heartbeat_at,
        "cpu_usage": agent.health.cpu_usage_percent,
        "memory_usage": agent.health.memory_usage_percent,
        "disk_usage": agent.health.disk_usage_percent,
        "uptime_seconds": agent.health.uptime_seconds,
        "jobs_completed": agent.statistics.total_jobs_completed,
        "jobs_failed": agent.statistics.total_jobs_failed,
        "error_message": agent.health.error_message,
    }


@router.post("/{agent_id}/disable")
async def disable_agent(
    agent_id: str,
    request: Request,
    user: CurrentUser = Depends(get_current_user),
) -> dict[str, Any]:
    _require_admin(user)
    service = _get_service(request)
    try:
        agent = service.disable_agent(agent_id)
    except Exception as exc:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=str(exc)) from exc
    return {"message": f"Agent '{agent_id}' disabled", "state": agent.state.value}


@router.post("/{agent_id}/enable")
async def enable_agent(
    agent_id: str,
    request: Request,
    user: CurrentUser = Depends(get_current_user),
) -> dict[str, Any]:
    _require_admin(user)
    service = _get_service(request)
    try:
        agent = service.enable_agent(agent_id)
    except Exception as exc:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=str(exc)) from exc
    return {"message": f"Agent '{agent_id}' enabled", "state": agent.state.value}


@router.delete("/{agent_id}")
async def remove_agent(
    agent_id: str,
    request: Request,
    user: CurrentUser = Depends(get_current_user),
) -> dict[str, Any]:
    _require_admin(user)
    service = _get_service(request)
    try:
        service.remove_agent(agent_id)
    except Exception as exc:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=str(exc)) from exc
    return {"message": f"Agent '{agent_id}' removed"}


@router.post("/jobs/next")
async def assign_next_job(
    request: Request,
    body: dict[str, Any],
    user: CurrentUser = Depends(get_current_user),
) -> dict[str, Any]:
    _require_admin(user)
    service = _get_service(request)
    agent_id = body.get("agent_id", "")
    job_id = service.assign_next_job(agent_id)
    if not job_id:
        return {"message": "No job available", "job_id": None}
    return {"message": f"Job {job_id} assigned", "job_id": job_id}


@router.post("/jobs/progress")
async def report_job_progress(
    request: Request,
    body: dict[str, Any],
    user: CurrentUser = Depends(get_current_user),
) -> dict[str, Any]:
    _require_admin(user)
    service = _get_service(request)
    try:
        service.report_job_progress(body["agent_id"], body["job_id"], body.get("progress", 0.0))
    except Exception as exc:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=str(exc)) from exc
    return {"message": "Progress reported"}


@router.post("/jobs/complete")
async def complete_job(
    request: Request,
    body: dict[str, Any],
    user: CurrentUser = Depends(get_current_user),
) -> dict[str, Any]:
    _require_admin(user)
    service = _get_service(request)
    try:
        service.complete_job(body["agent_id"], body["job_id"])
    except Exception as exc:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=str(exc)) from exc
    return {"message": "Job completed"}


@router.post("/jobs/fail")
async def fail_job(
    request: Request,
    body: dict[str, Any],
    user: CurrentUser = Depends(get_current_user),
) -> dict[str, Any]:
    _require_admin(user)
    service = _get_service(request)
    try:
        service.fail_job(body["agent_id"], body["job_id"], body.get("error", ""))
    except Exception as exc:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=str(exc)) from exc
    return {"message": "Job failed"}
