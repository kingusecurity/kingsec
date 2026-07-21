"""Resume a paused scheduled scan."""

from __future__ import annotations

from datetime import UTC, datetime

from kingsec.application.ports.outbound.audit_publisher import AuditPublisher
from kingsec.application.ports.outbound.schedule_repository import ScheduleRepositoryPort
from kingsec.domain.audit import AuditAction, AuditEntry
from kingsec.domain.schedule import ScanSchedule, ScheduleStatus

from .create_schedule import _to_view
from .schedule_dto import ResumeScheduleRequest, ResumeScheduleResponse


class ResumeSchedule:
    def __init__(self, repository: ScheduleRepositoryPort, audit_publisher: AuditPublisher) -> None:
        self._repository = repository
        self._audit_publisher = audit_publisher

    def execute(self, request: ResumeScheduleRequest) -> ResumeScheduleResponse:
        existing = self._repository.find_by_id(request.schedule_id)
        if existing is None:
            from kingsec.application.errors import ApplicationError
            raise ApplicationError(f"schedule '{request.schedule_id}' not found")

        updated = ScanSchedule(
            id=existing.id, name=existing.name, description=existing.description,
            owner_user_id=existing.owner_user_id, target=existing.target,
            scanner_ids=existing.scanner_ids, config=existing.config,
            schedule_type=existing.schedule_type, cron_expression=existing.cron_expression,
            timezone=existing.timezone,
            enabled=existing.enabled, paused=False,
            created_at=existing.created_at, updated_at=datetime.now(UTC).isoformat(),
            last_run=existing.last_run, next_run=existing.next_run,
            retry_policy=existing.retry_policy, current_retry_count=existing.current_retry_count,
            status=ScheduleStatus.ACTIVE if existing.enabled else ScheduleStatus.DISABLED,
        )
        self._repository.save(updated)

        self._audit_publisher.record(
            AuditEntry(
                action=AuditAction.SCHEDULE_RESUMED,
                resource_type="schedule",
                resource_id=request.schedule_id,
                user_id=request.requesting_user_id,
            )
        )

        return ResumeScheduleResponse(schedule=_to_view(updated))
