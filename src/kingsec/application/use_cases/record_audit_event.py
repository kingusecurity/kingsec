"""Use case: record an enterprise audit event."""

from __future__ import annotations

from datetime import UTC, datetime

from kingsec.domain.audit_event import (
    AuditAction,
    AuditEvent,
    AuditEventId,
    AuditOutcome,
    AuditSeverity,
)

from ..errors import ApplicationError
from ..ports.outbound.audit_event_repository import AuditEventRepository
from .audit_dto import RecordAuditEventRequest, RecordAuditEventResponse


class RecordAuditEvent:
    """Record an immutable audit event."""

    def __init__(self, repo: AuditEventRepository) -> None:
        self._repo = repo

    def execute(self, request: RecordAuditEventRequest) -> RecordAuditEventResponse:
        import uuid

        try:
            action = AuditAction(request.action)
        except ValueError:
            raise ApplicationError(f"invalid audit action: {request.action}")

        try:
            outcome = AuditOutcome(request.outcome)
        except ValueError:
            raise ApplicationError(f"invalid audit outcome: {request.outcome}")

        try:
            severity = AuditSeverity(request.severity)
        except ValueError:
            raise ApplicationError(f"invalid audit severity: {request.severity}")

        event_id = AuditEventId(str(uuid.uuid4()))
        event = AuditEvent(
            id=event_id,
            timestamp=datetime.now(UTC).isoformat(),
            actor_id=request.actor_id,
            actor_type=request.actor_type,
            username=request.username,
            ip_address=request.ip_address,
            user_agent=request.user_agent,
            request_id=request.request_id,
            action=action,
            resource_type=request.resource_type,
            resource_id=request.resource_id,
            outcome=outcome,
            severity=severity,
            message=request.message,
            metadata=request.metadata or {},
        )

        self._repo.save(event)

        return RecordAuditEventResponse(event_id=str(event.id))
