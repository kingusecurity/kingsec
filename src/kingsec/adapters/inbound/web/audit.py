"""Web adapter for audit trail — enrichment decorator and admin query endpoint.

The ``EnrichedAuditPublisher`` wraps the real ``AuditPublisher`` and adds
HTTP request context (IP, user-agent, correlation ID) before delegating.
This keeps use cases HTTP-agnostic while ensuring every audit entry
recorded through the web layer carries full request metadata.

The admin query endpoint (``GET /api/v1/audit``) provides filtered access
to the audit trail. It requires ADMIN role.
"""

from __future__ import annotations

from typing import TYPE_CHECKING, Annotated

from fastapi import APIRouter, Depends, Query, Request

from kingsec.application.ports.outbound.audit_publisher import AuditPublisher
from kingsec.bootstrap.application import Application
from kingsec.domain.audit import AuditEntry

from .auth import require_admin

if TYPE_CHECKING:
    from kingsec.infrastructure.persistence.audit_repository import SqlAlchemyAuditRepository

router = APIRouter(prefix="/api/v1")


class EnrichedAuditPublisher(AuditPublisher):
    """Decorator that adds HTTP request context to audit entries.

    Wraps the real ``AuditPublisher`` and enriches each entry with
    IP address, user-agent, and correlation ID from the current request
    state (set by ``AuditContextMiddleware``).
    """

    def __init__(self, inner: AuditPublisher, request: Request) -> None:
        self._inner = inner
        self._request = request

    def record(self, entry: AuditEntry) -> None:
        """Enrich the entry with HTTP context and delegate to the inner publisher."""
        # Build enriched values from request state (set by AuditContextMiddleware).
        ip_address = getattr(self._request.state, "audit_ip", "") or ""
        user_agent = getattr(self._request.state, "audit_user_agent", "") or ""
        correlation_id = getattr(self._request.state, "audit_correlation_id", "") or ""

        # Create a new entry with enriched fields (frozen dataclass, can't mutate).
        enriched = AuditEntry(
            action=entry.action,
            resource_type=entry.resource_type,
            resource_id=entry.resource_id,
            success=entry.success,
            reason=entry.reason,
            timestamp=entry.timestamp,
            user_id=entry.user_id,
            username=entry.username,
            role=entry.role,
            ip_address=entry.ip_address or ip_address,
            user_agent=entry.user_agent or user_agent,
            correlation_id=entry.correlation_id or correlation_id,
            metadata=entry.metadata,
        )
        self._inner.record(enriched)


# ── Admin query schemas ──────────────────────────────────────────────────────


def _get_audit_repository(request: Request) -> SqlAlchemyAuditRepository:
    """Resolve the audit repository from the DI container."""
    app: Application = request.app.state.kingsec_app  # type: ignore[attr-defined]
    return app.resolve(AuditPublisher)  # type: ignore[return-value]


@router.get(
    "/audit",
    tags=["audit"],
    summary="Query audit trail",
    description=(
        "Query the security audit trail. Requires ADMIN role. "
        "Supports filtering by user, action, resource type, time range, and success/failure."
    ),
    dependencies=[Depends(require_admin)],
    responses={
        200: {"description": "Audit entries matching the query"},
        401: {"description": "Missing or invalid token"},
        403: {"description": "Insufficient permissions (ADMIN required)"},
    },
)
async def list_audit_entries(
    request: Request,
    user_id: Annotated[str | None, Query(description="Filter by user ID")] = None,
    action: Annotated[str | None, Query(description="Filter by action type")] = None,
    resource_type: Annotated[str | None, Query(description="Filter by resource type")] = None,
    since: Annotated[str | None, Query(description="Entries after this timestamp (ISO-8601)")] = None,
    until: Annotated[str | None, Query(description="Entries before this timestamp (ISO-8601)")] = None,
    success: Annotated[bool | None, Query(description="Filter by success/failure")] = None,
    limit: Annotated[int, Query(ge=1, le=200, description="Max results")] = 50,
    offset: Annotated[int, Query(ge=0, description="Results to skip")] = 0,
) -> dict:
    """Query audit trail entries with optional filters."""
    app: Application = request.app.state.kingsec_app  # type: ignore[attr-defined]
    repo: SqlAlchemyAuditRepository = app.resolve(AuditPublisher)  # type: ignore[assignment]

    entries = repo.list_entries(
        user_id=user_id,
        action=action,
        resource_type=resource_type,
        since=since,
        until=until,
        success_only=success,
        limit=limit,
        offset=offset,
    )
    total = repo.count_entries(user_id=user_id, action=action)

    return {
        "items": [
            {
                "action": e.action.value,
                "resource_type": e.resource_type,
                "resource_id": e.resource_id,
                "success": e.success,
                "reason": e.reason,
                "timestamp": e.timestamp,
                "user_id": e.user_id,
                "username": e.username,
                "role": e.role,
                "ip_address": e.ip_address,
                "correlation_id": e.correlation_id,
            }
            for e in entries
        ],
        "total": total,
        "limit": limit,
        "offset": offset,
    }
