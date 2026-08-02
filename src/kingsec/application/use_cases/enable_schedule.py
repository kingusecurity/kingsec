"""Enable a scheduled scan."""

from __future__ import annotations

from datetime import UTC, datetime

from kingsec.application.ports.outbound.audit_publisher import AuditPublisher
from kingsec.application.ports.outbound.schedule_repository import ScheduleRepositoryPort
from kingsec.domain.audit import AuditAction, AuditEntry
from kingsec.domain.schedule import ScanSchedule, ScheduleStatus

from .create_schedule import _to_view
from .schedule_dto import EnableScheduleRequest, EnableScheduleResponse


class EnableSchedule:
    def __init__(self, repository: ScheduleRepositoryPort, audit_publisher: AuditPublisher) -> None:
        self._repository = repository
        self._audit_publisher = audit_publisher

    def execute(self, request: EnableScheduleRequest) -> EnableScheduleResponse:
        existing = self._repository.find_by_id(request.schedule_id)
        if existing is None:
            from kingsec.application.errors import ScheduleNotFoundError

            raise ScheduleNotFoundError(f"schedule '{request.schedule_id}' not found")

        updated = ScanSchedule(
            id=existing.id,
            name=existing.name,
            description=existing.description,
            owner_user_id=existing.owner_user_id,
            target=existing.target,
            scanner_ids=existing.scanner_ids,
            config=existing.config,
            schedule_type=existing.schedule_type,
            cron_expression=existing.cron_expression,
            timezone=existing.timezone,
            enabled=True,
            paused=False,
            created_at=existing.created_at,
            updated_at=datetime.now(UTC).isoformat(),
            last_run=existing.last_run,
            next_run=existing.next_run,
            retry_policy=existing.retry_policy,
            current_retry_count=existing.current_retry_count,
            status=ScheduleStatus.ACTIVE,
        )
        self._repository.save(updated)

        self._audit_publisher.record(
            AuditEntry(
                action=AuditAction.SCHEDULE_ENABLED,
                resource_type="schedule",
                resource_id=request.schedule_id,
                user_id=request.requesting_user_id,
            )
        )

        return EnableScheduleResponse(schedule=_to_view(updated))
