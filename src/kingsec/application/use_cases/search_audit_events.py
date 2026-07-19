"""Use case: search audit events with filtering, pagination, and sorting."""

from __future__ import annotations

from ..ports.outbound.audit_event_repository import AuditEventRepository
from .audit_dto import AuditEventView, SearchAuditEventsRequest, SearchAuditEventsResponse


class SearchAuditEvents:
    """Search the audit event log."""

    def __init__(self, repo: AuditEventRepository) -> None:
        self._repo = repo

    def execute(self, request: SearchAuditEventsRequest) -> SearchAuditEventsResponse:
        items, total = self._repo.search(
            actor_id=request.actor_id,
            action=request.action,
            severity=request.severity,
            outcome=request.outcome,
            resource_type=request.resource_type,
            resource_id=request.resource_id,
            since=request.since,
            until=request.until,
            limit=min(max(request.limit, 1), 200),
            offset=max(request.offset, 0),
            sort_by=request.sort_by,
            sort_order=request.sort_order,
        )

        return SearchAuditEventsResponse(
            items=tuple(AuditEventView.from_domain(e) for e in items),
            total=total,
            limit=request.limit,
            offset=request.offset,
        )
