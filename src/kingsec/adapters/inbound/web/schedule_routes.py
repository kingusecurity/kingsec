"""FastAPI routes for scheduled scan management."""

from __future__ import annotations

from typing import Annotated

from fastapi import APIRouter, Depends, Path, Request, status

from kingsec.application.use_cases.create_schedule import CreateSchedule
from kingsec.application.use_cases.delete_schedule import DeleteSchedule
from kingsec.application.use_cases.disable_schedule import DisableSchedule
from kingsec.application.use_cases.enable_schedule import EnableSchedule
from kingsec.application.use_cases.find_due_schedules import FindDueSchedules
from kingsec.application.use_cases.get_schedule import GetSchedule
from kingsec.application.use_cases.list_schedules import ListSchedules
from kingsec.application.use_cases.pause_schedule import PauseSchedule
from kingsec.application.use_cases.resume_schedule import ResumeSchedule
from kingsec.application.use_cases.schedule_dto import (
    CreateScheduleRequest,
    DeleteScheduleRequest,
    DisableScheduleRequest,
    EnableScheduleRequest,
    GetScheduleRequest,
    ListSchedulesRequest,
    PauseScheduleRequest,
    ResumeScheduleRequest,
    TriggerScheduleNowRequest,
    UpdateScheduleRequest,
)
from kingsec.application.use_cases.trigger_schedule_now import TriggerScheduleNow
from kingsec.application.use_cases.update_schedule import UpdateSchedule
from kingsec.bootstrap.application import Application
from kingsec.domain import Role

from .auth import CurrentUser, require_role
from .schedule_schemas import (
    CreateScheduleBody,
    CreateScheduleResponse,
    DeleteScheduleResponse,
    DisableScheduleResponse,
    EnableScheduleResponse,
    ListSchedulesResponse,
    PauseScheduleResponse,
    ResumeScheduleResponse,
    ScheduleViewResponse,
    TriggerScheduleNowResponse,
    UpdateScheduleBody,
    UpdateScheduleResponse,
)

router = APIRouter(prefix="/api/v1")


def _get_create_schedule_uc(request: Request) -> CreateSchedule:
    app: Application = request.app.state.kingsec_app
    return app.resolve(CreateSchedule)


def _get_update_schedule_uc(request: Request) -> UpdateSchedule:
    app: Application = request.app.state.kingsec_app
    return app.resolve(UpdateSchedule)


def _get_delete_schedule_uc(request: Request) -> DeleteSchedule:
    app: Application = request.app.state.kingsec_app
    return app.resolve(DeleteSchedule)


def _get_pause_schedule_uc(request: Request) -> PauseSchedule:
    app: Application = request.app.state.kingsec_app
    return app.resolve(PauseSchedule)


def _get_resume_schedule_uc(request: Request) -> ResumeSchedule:
    app: Application = request.app.state.kingsec_app
    return app.resolve(ResumeSchedule)


def _get_enable_schedule_uc(request: Request) -> EnableSchedule:
    app: Application = request.app.state.kingsec_app
    return app.resolve(EnableSchedule)


def _get_disable_schedule_uc(request: Request) -> DisableSchedule:
    app: Application = request.app.state.kingsec_app
    return app.resolve(DisableSchedule)


def _get_trigger_schedule_uc(request: Request) -> TriggerScheduleNow:
    app: Application = request.app.state.kingsec_app
    return app.resolve(TriggerScheduleNow)


def _get_list_schedules_uc(request: Request) -> ListSchedules:
    app: Application = request.app.state.kingsec_app
    return app.resolve(ListSchedules)


def _get_get_schedule_uc(request: Request) -> GetSchedule:
    app: Application = request.app.state.kingsec_app
    return app.resolve(GetSchedule)


def _get_find_due_uc(request: Request) -> FindDueSchedules:
    app: Application = request.app.state.kingsec_app
    return app.resolve(FindDueSchedules)


@router.get(
    "/schedules",
    response_model=ListSchedulesResponse,
    tags=["schedules"],
    summary="List schedules",
    description="List all scheduled scans. Admins see all; normal users see only their own.",
)
async def list_schedules(
    current_user: CurrentUser = Depends(require_role(Role.VIEWER)),
    list_uc: ListSchedules = Depends(_get_list_schedules_uc),
) -> ListSchedulesResponse:
    result = list_uc.execute(
        ListSchedulesRequest(
            requesting_user_id=current_user.user_id,
            is_admin=current_user.role == Role.ADMIN,
        )
    )
    return ListSchedulesResponse(
        items=[ScheduleViewResponse(**{
            "id": s.id, "name": s.name, "description": s.description,
            "owner_user_id": s.owner_user_id, "target": s.target,
            "scanner_ids": list(s.scanner_ids), "config": dict(s.config),
            "schedule_type": s.schedule_type, "cron_expression": s.cron_expression,
            "timezone": s.timezone, "enabled": s.enabled, "paused": s.paused,
            "status": s.status, "created_at": s.created_at, "updated_at": s.updated_at,
            "last_run": s.last_run, "next_run": s.next_run,
            "retry_strategy": s.retry_strategy, "max_retries": s.max_retries,
            "retry_delay_seconds": s.retry_delay_seconds,
            "current_retry_count": s.current_retry_count,
        }) for s in result.schedules]
    )


@router.get(
    "/schedules/due",
    response_model=ListSchedulesResponse,
    tags=["schedules"],
    summary="Find due schedules",
    description="Find all schedules due for execution. Admin only.",
    dependencies=[Depends(require_role(Role.ADMIN))],
)
async def find_due_schedules(
    find_uc: FindDueSchedules = Depends(_get_find_due_uc),
) -> ListSchedulesResponse:
    result = find_uc.execute()
    return ListSchedulesResponse(
        items=[ScheduleViewResponse(**{
            "id": s.id, "name": s.name, "description": s.description,
            "owner_user_id": s.owner_user_id, "target": s.target,
            "scanner_ids": list(s.scanner_ids), "config": dict(s.config),
            "schedule_type": s.schedule_type, "cron_expression": s.cron_expression,
            "timezone": s.timezone, "enabled": s.enabled, "paused": s.paused,
            "status": s.status, "created_at": s.created_at, "updated_at": s.updated_at,
            "last_run": s.last_run, "next_run": s.next_run,
            "retry_strategy": s.retry_strategy, "max_retries": s.max_retries,
            "retry_delay_seconds": s.retry_delay_seconds,
            "current_retry_count": s.current_retry_count,
        }) for s in result.schedules]
    )


@router.post(
    "/schedules",
    response_model=CreateScheduleResponse,
    status_code=status.HTTP_201_CREATED,
    tags=["schedules"],
    summary="Create schedule",
    description="Create a new scheduled scan.",
)
async def create_schedule(
    body: CreateScheduleBody,
    current_user: CurrentUser = Depends(require_role(Role.ANALYST)),
    create_uc: CreateSchedule = Depends(_get_create_schedule_uc),
) -> CreateScheduleResponse:
    result = create_uc.execute(
        CreateScheduleRequest(
            name=body.name,
            description=body.description,
            owner_user_id=current_user.user_id,
            target=body.target,
            scanner_ids=body.scanner_ids,
            config=dict(body.config),
            schedule_type=body.schedule_type,
            cron_expression=body.cron_expression,
            timezone=body.timezone,
            retry_strategy=body.retry_strategy,
            max_retries=body.max_retries,
            retry_delay_seconds=body.retry_delay_seconds,
        )
    )
    s = result.schedule
    return CreateScheduleResponse(
        schedule=ScheduleViewResponse(
            id=s.id, name=s.name, description=s.description,
            owner_user_id=s.owner_user_id, target=s.target,
            scanner_ids=list(s.scanner_ids), config=dict(s.config),
            schedule_type=s.schedule_type, cron_expression=s.cron_expression,
            timezone=s.timezone, enabled=s.enabled, paused=s.paused,
            status=s.status, created_at=s.created_at, updated_at=s.updated_at,
            last_run=s.last_run, next_run=s.next_run,
            retry_strategy=s.retry_strategy, max_retries=s.max_retries,
            retry_delay_seconds=s.retry_delay_seconds,
            current_retry_count=s.current_retry_count,
        )
    )


@router.get(
    "/schedules/{schedule_id}",
    response_model=CreateScheduleResponse,
    tags=["schedules"],
    summary="Get schedule",
    description="Get a single scheduled scan by ID.",
)
async def get_schedule(
    schedule_id: Annotated[str, Path(description="Schedule ID")],
    current_user: CurrentUser = Depends(require_role(Role.VIEWER)),
    get_uc: GetSchedule = Depends(_get_get_schedule_uc),
) -> CreateScheduleResponse:
    result = get_uc.execute(GetScheduleRequest(schedule_id=schedule_id))
    s = result.schedule
    return CreateScheduleResponse(
        schedule=ScheduleViewResponse(
            id=s.id, name=s.name, description=s.description,
            owner_user_id=s.owner_user_id, target=s.target,
            scanner_ids=list(s.scanner_ids), config=dict(s.config),
            schedule_type=s.schedule_type, cron_expression=s.cron_expression,
            timezone=s.timezone, enabled=s.enabled, paused=s.paused,
            status=s.status, created_at=s.created_at, updated_at=s.updated_at,
            last_run=s.last_run, next_run=s.next_run,
            retry_strategy=s.retry_strategy, max_retries=s.max_retries,
            retry_delay_seconds=s.retry_delay_seconds,
            current_retry_count=s.current_retry_count,
        )
    )


@router.put(
    "/schedules/{schedule_id}",
    response_model=UpdateScheduleResponse,
    tags=["schedules"],
    summary="Update schedule",
    description="Update an existing scheduled scan.",
)
async def update_schedule(
    schedule_id: Annotated[str, Path(description="Schedule ID")],
    body: UpdateScheduleBody,
    current_user: CurrentUser = Depends(require_role(Role.ANALYST)),
    update_uc: UpdateSchedule = Depends(_get_update_schedule_uc),
) -> UpdateScheduleResponse:
    result = update_uc.execute(
        UpdateScheduleRequest(
            schedule_id=schedule_id,
            name=body.name,
            description=body.description,
            target=body.target,
            scanner_ids=body.scanner_ids,
            config=dict(body.config) if body.config is not None else None,
            schedule_type=body.schedule_type,
            cron_expression=body.cron_expression,
            timezone=body.timezone,
            retry_strategy=body.retry_strategy,
            max_retries=body.max_retries,
            retry_delay_seconds=body.retry_delay_seconds,
        )
    )
    s = result.schedule
    return UpdateScheduleResponse(
        schedule=ScheduleViewResponse(
            id=s.id, name=s.name, description=s.description,
            owner_user_id=s.owner_user_id, target=s.target,
            scanner_ids=list(s.scanner_ids), config=dict(s.config),
            schedule_type=s.schedule_type, cron_expression=s.cron_expression,
            timezone=s.timezone, enabled=s.enabled, paused=s.paused,
            status=s.status, created_at=s.created_at, updated_at=s.updated_at,
            last_run=s.last_run, next_run=s.next_run,
            retry_strategy=s.retry_strategy, max_retries=s.max_retries,
            retry_delay_seconds=s.retry_delay_seconds,
            current_retry_count=s.current_retry_count,
        )
    )


@router.delete(
    "/schedules/{schedule_id}",
    status_code=status.HTTP_200_OK,
    tags=["schedules"],
    summary="Delete schedule",
    description="Delete a scheduled scan.",
)
async def delete_schedule(
    schedule_id: Annotated[str, Path(description="Schedule ID")],
    current_user: CurrentUser = Depends(require_role(Role.ANALYST)),
    delete_uc: DeleteSchedule = Depends(_get_delete_schedule_uc),
) -> DeleteScheduleResponse:
    result = delete_uc.execute(
        DeleteScheduleRequest(
            schedule_id=schedule_id,
            requesting_user_id=current_user.user_id,
        )
    )
    return DeleteScheduleResponse(success=result.success)


@router.post(
    "/schedules/{schedule_id}/pause",
    response_model=PauseScheduleResponse,
    tags=["schedules"],
    summary="Pause schedule",
    description="Pause a scheduled scan.",
)
async def pause_schedule(
    schedule_id: Annotated[str, Path(description="Schedule ID")],
    current_user: CurrentUser = Depends(require_role(Role.ANALYST)),
    pause_uc: PauseSchedule = Depends(_get_pause_schedule_uc),
) -> PauseScheduleResponse:
    result = pause_uc.execute(
        PauseScheduleRequest(
            schedule_id=schedule_id,
            requesting_user_id=current_user.user_id,
        )
    )
    s = result.schedule
    return PauseScheduleResponse(
        schedule=ScheduleViewResponse(
            id=s.id, name=s.name, description=s.description,
            owner_user_id=s.owner_user_id, target=s.target,
            scanner_ids=list(s.scanner_ids), config=dict(s.config),
            schedule_type=s.schedule_type, cron_expression=s.cron_expression,
            timezone=s.timezone, enabled=s.enabled, paused=s.paused,
            status=s.status, created_at=s.created_at, updated_at=s.updated_at,
            last_run=s.last_run, next_run=s.next_run,
            retry_strategy=s.retry_strategy, max_retries=s.max_retries,
            retry_delay_seconds=s.retry_delay_seconds,
            current_retry_count=s.current_retry_count,
        )
    )


@router.post(
    "/schedules/{schedule_id}/resume",
    response_model=ResumeScheduleResponse,
    tags=["schedules"],
    summary="Resume schedule",
    description="Resume a paused scheduled scan.",
)
async def resume_schedule(
    schedule_id: Annotated[str, Path(description="Schedule ID")],
    current_user: CurrentUser = Depends(require_role(Role.ANALYST)),
    resume_uc: ResumeSchedule = Depends(_get_resume_schedule_uc),
) -> ResumeScheduleResponse:
    result = resume_uc.execute(
        ResumeScheduleRequest(
            schedule_id=schedule_id,
            requesting_user_id=current_user.user_id,
        )
    )
    s = result.schedule
    return ResumeScheduleResponse(
        schedule=ScheduleViewResponse(
            id=s.id, name=s.name, description=s.description,
            owner_user_id=s.owner_user_id, target=s.target,
            scanner_ids=list(s.scanner_ids), config=dict(s.config),
            schedule_type=s.schedule_type, cron_expression=s.cron_expression,
            timezone=s.timezone, enabled=s.enabled, paused=s.paused,
            status=s.status, created_at=s.created_at, updated_at=s.updated_at,
            last_run=s.last_run, next_run=s.next_run,
            retry_strategy=s.retry_strategy, max_retries=s.max_retries,
            retry_delay_seconds=s.retry_delay_seconds,
            current_retry_count=s.current_retry_count,
        )
    )


@router.post(
    "/schedules/{schedule_id}/enable",
    response_model=EnableScheduleResponse,
    tags=["schedules"],
    summary="Enable schedule",
    description="Enable a disabled scheduled scan.",
)
async def enable_schedule(
    schedule_id: Annotated[str, Path(description="Schedule ID")],
    current_user: CurrentUser = Depends(require_role(Role.ANALYST)),
    enable_uc: EnableSchedule = Depends(_get_enable_schedule_uc),
) -> EnableScheduleResponse:
    result = enable_uc.execute(
        EnableScheduleRequest(
            schedule_id=schedule_id,
            requesting_user_id=current_user.user_id,
        )
    )
    s = result.schedule
    return EnableScheduleResponse(
        schedule=ScheduleViewResponse(
            id=s.id, name=s.name, description=s.description,
            owner_user_id=s.owner_user_id, target=s.target,
            scanner_ids=list(s.scanner_ids), config=dict(s.config),
            schedule_type=s.schedule_type, cron_expression=s.cron_expression,
            timezone=s.timezone, enabled=s.enabled, paused=s.paused,
            status=s.status, created_at=s.created_at, updated_at=s.updated_at,
            last_run=s.last_run, next_run=s.next_run,
            retry_strategy=s.retry_strategy, max_retries=s.max_retries,
            retry_delay_seconds=s.retry_delay_seconds,
            current_retry_count=s.current_retry_count,
        )
    )


@router.post(
    "/schedules/{schedule_id}/disable",
    response_model=DisableScheduleResponse,
    tags=["schedules"],
    summary="Disable schedule",
    description="Disable an active scheduled scan.",
)
async def disable_schedule(
    schedule_id: Annotated[str, Path(description="Schedule ID")],
    current_user: CurrentUser = Depends(require_role(Role.ANALYST)),
    disable_uc: DisableSchedule = Depends(_get_disable_schedule_uc),
) -> DisableScheduleResponse:
    result = disable_uc.execute(
        DisableScheduleRequest(
            schedule_id=schedule_id,
            requesting_user_id=current_user.user_id,
        )
    )
    s = result.schedule
    return DisableScheduleResponse(
        schedule=ScheduleViewResponse(
            id=s.id, name=s.name, description=s.description,
            owner_user_id=s.owner_user_id, target=s.target,
            scanner_ids=list(s.scanner_ids), config=dict(s.config),
            schedule_type=s.schedule_type, cron_expression=s.cron_expression,
            timezone=s.timezone, enabled=s.enabled, paused=s.paused,
            status=s.status, created_at=s.created_at, updated_at=s.updated_at,
            last_run=s.last_run, next_run=s.next_run,
            retry_strategy=s.retry_strategy, max_retries=s.max_retries,
            retry_delay_seconds=s.retry_delay_seconds,
            current_retry_count=s.current_retry_count,
        )
    )


@router.post(
    "/schedules/{schedule_id}/trigger",
    response_model=TriggerScheduleNowResponse,
    tags=["schedules"],
    summary="Trigger schedule now",
    description="Immediately trigger a scheduled scan.",
)
async def trigger_schedule(
    schedule_id: Annotated[str, Path(description="Schedule ID")],
    current_user: CurrentUser = Depends(require_role(Role.ANALYST)),
    trigger_uc: TriggerScheduleNow = Depends(_get_trigger_schedule_uc),
) -> TriggerScheduleNowResponse:
    result = trigger_uc.execute(
        TriggerScheduleNowRequest(
            schedule_id=schedule_id,
            requesting_user_id=current_user.user_id,
        )
    )
    s = result.schedule
    return TriggerScheduleNowResponse(
        schedule=ScheduleViewResponse(
            id=s.id, name=s.name, description=s.description,
            owner_user_id=s.owner_user_id, target=s.target,
            scanner_ids=list(s.scanner_ids), config=dict(s.config),
            schedule_type=s.schedule_type, cron_expression=s.cron_expression,
            timezone=s.timezone, enabled=s.enabled, paused=s.paused,
            status=s.status, created_at=s.created_at, updated_at=s.updated_at,
            last_run=s.last_run, next_run=s.next_run,
            retry_strategy=s.retry_strategy, max_retries=s.max_retries,
            retry_delay_seconds=s.retry_delay_seconds,
            current_retry_count=s.current_retry_count,
        ),
        job_id=result.job_id,
    )
