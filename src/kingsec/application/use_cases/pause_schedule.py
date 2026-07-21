"""Pause a scheduled scan."""

from __future__ import annotations

from datetime import UTC, datetime

from kingsec.application.ports.outbound.audit_publisher import AuditPublisher
from kingsec.application.ports.outbound.schedule_repository import ScheduleRepositoryPort
from kingsec.domain.audit import AuditAction, AuditEntry
from kingsec.domain.schedule import ScanSchedule, ScheduleStatus

from .create_schedule import _to_view
from .schedule_dto import PauseScheduleRequest, PauseScheduleResponse


class PauseSchedule:
    def __init__(self, repository: ScheduleRepositoryPort, audit_publisher: AuditPublisher) -> None:
        self._repository = repository
        self._audit_publisher = audit_publisher

    def execute(self, request: PauseScheduleRequest) -> PauseScheduleResponse:
        existing = self._repository.find_by_id(request.schedule_id)
        if existing is None:
            from kingsec.application.errors import ApplicationError

            raise ApplicationError(f"schedule '{request.schedule_id}' not found")

        paused = existing.with_status(ScheduleStatus.PAUSED)
        updated = ScanSchedule(
            id=paused.id,
            name=paused.name,
            description=paused.description,
            owner_user_id=paused.owner_user_id,
            target=paused.target,
            scanner_ids=paused.scanner_ids,
            config=paused.config,
            schedule_type=paused.schedule_type,
            cron_expression=paused.cron_expression,
            timezone=paused.timezone,
            enabled=paused.enabled,
            paused=True,
            created_at=paused.created_at,
            updated_at=datetime.now(UTC).isoformat(),
            last_run=paused.last_run,
            next_run=paused.next_run,
            retry_policy=paused.retry_policy,
            current_retry_count=paused.current_retry_count,
            status=paused.status,
        )
        self._repository.save(updated)

        self._audit_publisher.record(
            AuditEntry(
                action=AuditAction.SCHEDULE_PAUSED,
                resource_type="schedule",
                resource_id=request.schedule_id,
                user_id=request.requesting_user_id,
            )
        )

        return PauseScheduleResponse(schedule=_to_view(updated))
