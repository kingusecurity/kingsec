"""Create a new scheduled scan."""

from __future__ import annotations

from datetime import UTC, datetime
from uuid import uuid4

from kingsec.application.ports.outbound.audit_publisher import AuditPublisher
from kingsec.application.ports.outbound.schedule_repository import ScheduleRepositoryPort
from kingsec.domain.audit import AuditAction, AuditEntry
from kingsec.domain.schedule import (
    RetryPolicy,
    RetryStrategy,
    ScanSchedule,
    ScheduleId,
    ScheduleStatus,
    ScheduleType,
)

from .schedule_dto import CreateScheduleRequest, CreateScheduleResponse, ScheduleView


class CreateSchedule:
    def __init__(self, repository: ScheduleRepositoryPort, audit_publisher: AuditPublisher) -> None:
        self._repository = repository
        self._audit_publisher = audit_publisher

    def execute(self, request: CreateScheduleRequest) -> CreateScheduleResponse:
        try:
            stype = ScheduleType(request.schedule_type)
        except ValueError:
            stype = ScheduleType.ONE_TIME

        try:
            rstrat = RetryStrategy(request.retry_strategy)
        except ValueError:
            rstrat = RetryStrategy.NO_RETRY

        now = datetime.now(UTC).isoformat()
        schedule = ScanSchedule(
            id=ScheduleId(value=str(uuid4())),
            name=request.name,
            description=request.description,
            owner_user_id=request.owner_user_id,
            target=request.target,
            scanner_ids=tuple(request.scanner_ids),
            config=dict(request.config),
            schedule_type=stype,
            cron_expression=request.cron_expression,
            timezone=request.timezone,
            enabled=True,
            paused=False,
            created_at=now,
            updated_at=now,
            status=ScheduleStatus.ACTIVE,
            retry_policy=RetryPolicy(
                strategy=rstrat,
                max_retries=request.max_retries,
                retry_delay_seconds=request.retry_delay_seconds,
            ),
        )

        self._repository.save(schedule)

        self._audit_publisher.record(
            AuditEntry(
                action=AuditAction.SCHEDULE_CREATED,
                resource_type="schedule",
                resource_id=str(schedule.id),
                user_id=request.owner_user_id,
                metadata={"name": request.name, "schedule_type": request.schedule_type},
            )
        )

        return CreateScheduleResponse(schedule=_to_view(schedule))


def _to_view(s: ScanSchedule) -> ScheduleView:
    return ScheduleView(
        id=str(s.id),
        name=s.name,
        description=s.description,
        owner_user_id=s.owner_user_id,
        target=s.target,
        scanner_ids=list(s.scanner_ids),
        config=dict(s.config),
        schedule_type=s.schedule_type.value,
        cron_expression=s.cron_expression,
        timezone=s.timezone,
        enabled=s.enabled,
        paused=s.paused,
        status=s.status.value,
        created_at=s.created_at,
        updated_at=s.updated_at,
        last_run=s.last_run,
        next_run=s.next_run,
        retry_strategy=s.retry_policy.strategy.value,
        max_retries=s.retry_policy.max_retries,
        retry_delay_seconds=s.retry_policy.retry_delay_seconds,
        current_retry_count=s.current_retry_count,
    )
