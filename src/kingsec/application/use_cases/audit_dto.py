"""DTOs for enterprise audit use cases."""

from __future__ import annotations

from dataclasses import dataclass

from kingsec.domain.audit_event import AuditEvent


@dataclass(frozen=True)
class RecordAuditEventRequest:
    """Request to record an audit event."""

    actor_id: str
    actor_type: str
    username: str
    ip_address: str
    user_agent: str
    request_id: str
    action: str
    resource_type: str
    resource_id: str
    outcome: str
    severity: str
    message: str
    metadata: dict[str, object] | None = None


@dataclass(frozen=True)
class RecordAuditEventResponse:
    """Response from recording an audit event."""

    event_id: str


@dataclass(frozen=True)
class AuditEventView:
    """Public view of an audit event (no sensitive fields)."""

    event_id: str
    timestamp: str
    actor_id: str
    actor_type: str
    username: str
    ip_address: str
    user_agent: str
    request_id: str
    action: str
    resource_type: str
    resource_id: str
    outcome: str
    severity: str
    message: str
    metadata: dict[str, object]

    @classmethod
    def from_domain(cls, event: AuditEvent) -> AuditEventView:
        return cls(
            event_id=str(event.id),
            timestamp=event.timestamp,
            actor_id=event.actor_id,
            actor_type=event.actor_type,
            username=event.username,
            ip_address=event.ip_address,
            user_agent=event.user_agent,
            request_id=event.request_id,
            action=event.action.value,
            resource_type=event.resource_type,
            resource_id=event.resource_id,
            outcome=event.outcome.value,
            severity=event.severity.value,
            message=event.message,
            metadata=event.metadata,
        )


@dataclass(frozen=True)
class SearchAuditEventsRequest:
    """Request to search audit events."""

    actor_id: str | None = None
    action: str | None = None
    severity: str | None = None
    outcome: str | None = None
    resource_type: str | None = None
    resource_id: str | None = None
    since: str | None = None
    until: str | None = None
    limit: int = 50
    offset: int = 0
    sort_by: str = "timestamp"
    sort_order: str = "desc"


@dataclass(frozen=True)
class SearchAuditEventsResponse:
    """Response containing matching audit events."""

    items: tuple[AuditEventView, ...]
    total: int
    limit: int
    offset: int
