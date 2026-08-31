"""Web adapter for enterprise audit events — admin query endpoints.

Admin-only endpoints (``GET /audit/events``, ``GET /audit/events/{id}``)
with ``require_admin`` guard. Recording events has no HTTP boundary —
use cases call the repository directly.
"""

from __future__ import annotations

from typing import TYPE_CHECKING, Annotated, Any, cast

from fastapi import APIRouter, Depends, HTTPException, Query, Request, status

from kingsec.application.errors import LicenseRequiredError
from kingsec.application.services.licensing import LicenseGate
from kingsec.application.use_cases.audit_dto import SearchAuditEventsRequest
from kingsec.application.use_cases.search_audit_events import SearchAuditEvents

from .auth import require_admin

if TYPE_CHECKING:
    from kingsec.bootstrap.application import Application

router = APIRouter(prefix="/api/v1/audit", tags=["audit_events"])


def _get_app(request: Request) -> Application:
    return cast("Application", request.app.state.kingsec_app)


def _require_enterprise_audit(request: Request) -> None:
    """Enforce the Enterprise-edition ``enterprise_audit`` feature gate.

    Stacked with (never a substitute for) the ``require_admin`` role check
    already present on every route below: an Enterprise admin passes both,
    a non-Enterprise admin is stopped here, and a non-admin is stopped by
    ``require_admin`` regardless of edition.
    """
    app = _get_app(request)
    gate: LicenseGate | None = app.resolve(LicenseGate)
    if gate is not None and not gate.can_use_enterprise_audit():
        raise LicenseRequiredError("Enterprise audit events", gate.current_edition().value, required="an Enterprise")


@router.get(
    "/events",
    summary="Query enterprise audit events",
    description=(
        "Query the enterprise audit event log. Requires ADMIN role. "
        "Supports filtering by actor, action, severity, outcome, resource, "
        "and time range. Results are paginated and sortable."
    ),
    dependencies=[Depends(require_admin), Depends(_require_enterprise_audit)],
    responses={
        200: {"description": "Audit events matching the query"},
        401: {"description": "Missing or invalid authentication"},
        403: {"description": "Insufficient permissions (ADMIN required, Enterprise edition required)"},
    },
)
async def list_audit_events(
    request: Request,
    actor_id: Annotated[str | None, Query(description="Filter by actor ID")] = None,
    action: Annotated[str | None, Query(description="Filter by action type")] = None,
    severity: Annotated[str | None, Query(description="Filter by severity (info, warning, error, critical)")] = None,
    outcome: Annotated[str | None, Query(description="Filter by outcome (success, failure, denied)")] = None,
    resource_type: Annotated[str | None, Query(description="Filter by resource type")] = None,
    resource_id: Annotated[str | None, Query(description="Filter by resource ID")] = None,
    since: Annotated[str | None, Query(description="Events after this timestamp (ISO-8601)")] = None,
    until: Annotated[str | None, Query(description="Events before this timestamp (ISO-8601)")] = None,
    limit: Annotated[int, Query(ge=1, le=200, description="Max results")] = 50,
    offset: Annotated[int, Query(ge=0, description="Results to skip")] = 0,
    sort_by: Annotated[str, Query(description="Sort field (timestamp, actor_id, action, severity)")] = "timestamp",
    sort_order: Annotated[str, Query(description="Sort order (asc or desc)", pattern="^(asc|desc)$")] = "desc",
) -> dict[str, Any]:
    """Query enterprise audit events with optional filters."""
    app = _get_app(request)
    use_case: SearchAuditEvents = app.resolve(SearchAuditEvents)

    result = use_case.execute(
        SearchAuditEventsRequest(
            actor_id=actor_id,
            action=action,
            severity=severity,
            outcome=outcome,
            resource_type=resource_type,
            resource_id=resource_id,
            since=since,
            until=until,
            limit=limit,
            offset=offset,
            sort_by=sort_by,
            sort_order=sort_order,
        )
    )

    return {
        "items": [
            {
                "event_id": v.event_id,
                "timestamp": v.timestamp,
                "actor_id": v.actor_id,
                "actor_type": v.actor_type,
                "username": v.username,
                "ip_address": v.ip_address,
                "request_id": v.request_id,
                "action": v.action,
                "resource_type": v.resource_type,
                "resource_id": v.resource_id,
                "outcome": v.outcome,
                "severity": v.severity,
                "message": v.message,
            }
            for v in result.items
        ],
        "total": result.total,
        "limit": result.limit,
        "offset": result.offset,
    }


@router.get(
    "/events/{event_id}",
    summary="Get a single audit event by ID",
    description="Retrieve a specific enterprise audit event by its ID. Requires ADMIN role.",
    dependencies=[Depends(require_admin), Depends(_require_enterprise_audit)],
    responses={
        200: {"description": "Audit event details"},
        401: {"description": "Missing or invalid authentication"},
        403: {"description": "Insufficient permissions (ADMIN required, Enterprise edition required)"},
        404: {"description": "Audit event not found"},
    },
)
async def get_audit_event(
    request: Request,
    event_id: str,
) -> dict[str, Any]:
    """Get a single audit event by its ID."""
    from kingsec.application.ports.outbound.audit_event_repository import AuditEventRepository
    from kingsec.domain.audit_event import AuditEventId

    app = _get_app(request)
    repo: AuditEventRepository = app.resolve(AuditEventRepository)
    event = repo.find_by_id(AuditEventId(event_id))

    if event is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Audit event not found")

    return {
        "event_id": str(event.id),
        "timestamp": event.timestamp,
        "actor_id": event.actor_id,
        "actor_type": event.actor_type,
        "username": event.username,
        "ip_address": event.ip_address,
        "user_agent": event.user_agent,
        "request_id": event.request_id,
        "action": event.action.value,
        "resource_type": event.resource_type,
        "resource_id": event.resource_id,
        "outcome": event.outcome.value,
        "severity": event.severity.value,
        "message": event.message,
        "metadata": event.metadata,
    }
