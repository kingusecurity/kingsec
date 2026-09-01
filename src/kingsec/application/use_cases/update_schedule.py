"""Update an existing scheduled scan."""

from __future__ import annotations

from datetime import UTC, datetime

from kingsec.application._support import check_schedule_access
from kingsec.application.ports.outbound.audit_publisher import AuditPublisher
from kingsec.application.ports.outbound.schedule_repository import ScheduleRepositoryPort
from kingsec.domain.audit import AuditAction, AuditEntry
from kingsec.domain.schedule import ScanSchedule, ScheduleType

from .create_schedule import _to_view
from .schedule_dto import UpdateScheduleRequest, UpdateScheduleResponse


class UpdateSchedule:
    def __init__(self, repository: ScheduleRepositoryPort, audit_publisher: AuditPublisher) -> None:
        self._repository = repository
        self._audit_publisher = audit_publisher

    def execute(self, request: UpdateScheduleRequest) -> UpdateScheduleResponse:
        existing = self._repository.find_by_id(request.schedule_id)
        if existing is None:
            from kingsec.application.errors import ScheduleNotFoundError

            raise ScheduleNotFoundError(f"schedule '{request.schedule_id}' not found")

        # KSEC-69-01: authorization before any mutation is computed or persisted.
        check_schedule_access(existing, request.requesting_user_id, request.is_admin)

        stype = existing.schedule_type
        if request.schedule_type is not None:
            try:
                stype = ScheduleType(request.schedule_type)
            except ValueError:
                pass

        cron = request.cron_expression if request.cron_expression is not None else existing.cron_expression
        tz = request.timezone if request.timezone is not None else existing.timezone

        updated = ScanSchedule(
            id=existing.id,
            name=request.name if request.name is not None else existing.name,
            description=request.description if request.description is not None else existing.description,
            owner_user_id=existing.owner_user_id,
            target=request.target if request.target is not None else existing.target,
            scanner_ids=tuple(request.scanner_ids) if request.scanner_ids is not None else existing.scanner_ids,
            config=dict(request.config) if request.config is not None else existing.config,
            schedule_type=stype,
            cron_expression=cron,
            timezone=tz,
            enabled=existing.enabled,
            paused=existing.paused,
            created_at=existing.created_at,
            updated_at=datetime.now(UTC).isoformat(),
            last_run=existing.last_run,
            next_run=existing.next_run,
            retry_policy=existing.retry_policy,
            current_retry_count=existing.current_retry_count,
            status=existing.status,
            version=existing.version,
        )

        self._repository.save(updated)

        self._audit_publisher.record(
            AuditEntry(
                action=AuditAction.SCHEDULE_UPDATED,
                resource_type="schedule",
                resource_id=str(updated.id),
                metadata={"name": updated.name},
            )
        )

        return UpdateScheduleResponse(schedule=_to_view(updated))
