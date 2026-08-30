"""Delete a scheduled scan."""

from __future__ import annotations

from kingsec.application.ports.outbound.audit_publisher import AuditPublisher
from kingsec.application.ports.outbound.schedule_repository import ScheduleRepositoryPort
from kingsec.domain.audit import AuditAction, AuditEntry

from .schedule_dto import DeleteScheduleRequest, DeleteScheduleResponse


class DeleteSchedule:
    def __init__(self, repository: ScheduleRepositoryPort, audit_publisher: AuditPublisher) -> None:
        self._repository = repository
        self._audit_publisher = audit_publisher

    def execute(self, request: DeleteScheduleRequest) -> DeleteScheduleResponse:
        existing = self._repository.find_by_id(request.schedule_id)
        if existing is None:
            return DeleteScheduleResponse(success=False)

        # KSEC-69-01: deliberately returns the identical success=False
        # this use case already returns for "doesn't exist" above, rather
        # than raising ScheduleNotFoundError (the pattern every sibling
        # use case uses) - this use case's own established not-found
        # shape is a boolean result, not an exception, so a non-owner
        # must see that same shape or the two cases would become
        # distinguishable from each other.
        if not (request.is_admin or (existing.owner_user_id and existing.owner_user_id == request.requesting_user_id)):
            return DeleteScheduleResponse(success=False)

        self._repository.delete(request.schedule_id)

        self._audit_publisher.record(
            AuditEntry(
                action=AuditAction.SCHEDULE_DELETED,
                resource_type="schedule",
                resource_id=request.schedule_id,
                user_id=request.requesting_user_id,
            )
        )

        return DeleteScheduleResponse(success=True)
