"""Use case: create a new AuthorizationGrant (Phase 4)."""

from __future__ import annotations

import logging

from kingsec.application._support import build_authorization_grant, build_target_specification, parse_utc_datetime
from kingsec.application.dto import CreateAuthorizationGrantRequest, CreateAuthorizationGrantResponse
from kingsec.application.ports import AuditPublisher, AuthorizationGrantRepository
from kingsec.domain.audit import AuditAction, AuditEntry
from kingsec.domain.identifiers import AuthorizationGrantId


class CreateAuthorizationGrant:
    """Create and persist a new AuthorizationGrant."""

    def __init__(
        self,
        grants: AuthorizationGrantRepository,
        audit: AuditPublisher | None = None,
    ) -> None:
        self._grants = grants
        self._audit = audit

    def execute(self, request: CreateAuthorizationGrantRequest) -> CreateAuthorizationGrantResponse:
        spec = build_target_specification(request.target_specification_type, request.target_specification_value)
        valid_from = parse_utc_datetime(request.valid_from)
        valid_until = parse_utc_datetime(request.valid_until)

        grant = build_authorization_grant(
            grant_id=AuthorizationGrantId.generate(),
            authorized_by=request.authorized_by,
            authorizing_organization=request.authorizing_organization,
            target_specification=spec,
            valid_from=valid_from,
            valid_until=valid_until,
            created_by=request.created_by,
        )
        self._grants.save(grant)

        self._publish_audit(
            AuditEntry(
                action=AuditAction.AUTHORIZATION_GRANT_CREATED,
                resource_type="authorization_grant",
                resource_id=grant.id.value,
                success=True,
                username=request.created_by,
                metadata={
                    "target_specification_type": spec.type.value,
                    "target_specification_value": spec.value,
                    "authorized_by": request.authorized_by,
                    "authorizing_organization": request.authorizing_organization,
                },
            )
        )

        return CreateAuthorizationGrantResponse(
            grant_id=grant.id.value,
            target_specification_type=spec.type.value,
            target_specification_value=spec.value,
            valid_from=valid_from.isoformat(),
            valid_until=valid_until.isoformat(),
        )

    def _publish_audit(self, entry: AuditEntry) -> None:
        """Publish an audit entry if a publisher is configured (best-effort)."""
        if self._audit is None:
            return
        try:
            self._audit.record(entry)
        except Exception as exc:
            logging.getLogger(__name__).warning("audit publish failed (best-effort): %s", exc)
