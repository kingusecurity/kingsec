"""Trigger a scheduled scan immediately."""

from __future__ import annotations

from datetime import UTC, datetime

from kingsec.application._support import check_schedule_access
from kingsec.application.ports.job_service import JobServicePort
from kingsec.application.ports.outbound.audit_publisher import AuditPublisher
from kingsec.application.ports.outbound.schedule_repository import ScheduleRepositoryPort
from kingsec.domain.audit import AuditAction, AuditEntry

from .create_schedule import _to_view
from .schedule_dto import TriggerScheduleNowRequest, TriggerScheduleNowResponse


class TriggerScheduleNow:
    def __init__(
        self,
        repository: ScheduleRepositoryPort,
        job_service: JobServicePort,
        audit_publisher: AuditPublisher,
    ) -> None:
        self._repository = repository
        self._job_service = job_service
        self._audit_publisher = audit_publisher

    def execute(self, request: TriggerScheduleNowRequest) -> TriggerScheduleNowResponse:
        existing = self._repository.find_by_id(request.schedule_id)
        if existing is None:
            from kingsec.application.errors import ScheduleNotFoundError

            raise ScheduleNotFoundError(f"schedule '{request.schedule_id}' not found")

        # KSEC-69-01: authorization before the scanner job is submitted.
        check_schedule_access(existing, request.requesting_user_id, request.is_admin)

        job = self._job_service.submit_scan(target=existing.target, config={"schedule_id": str(existing.id)})
        now = datetime.now(UTC).isoformat()

        updated = existing.with_run_completed(next_run=existing.next_run, now=now)
        self._repository.save(updated)

        self._audit_publisher.record(
            AuditEntry(
                action=AuditAction.SCHEDULE_TRIGGERED,
                resource_type="schedule",
                resource_id=request.schedule_id,
                user_id=request.requesting_user_id,
                metadata={"job_id": str(job.id)},
            )
        )

        return TriggerScheduleNowResponse(
            schedule=_to_view(updated),
            job_id=str(job.id),
        )
