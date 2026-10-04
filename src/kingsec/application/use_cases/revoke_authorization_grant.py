"""Use case: revoke an existing AuthorizationGrant (Phase 4)."""

from __future__ import annotations

import logging
from datetime import UTC, datetime

from kingsec.application.dto import RevokeAuthorizationGrantRequest, RevokeAuthorizationGrantResponse
from kingsec.application.ports import AuditPublisher, AuthorizationGrantRepository
from kingsec.domain.audit import AuditAction, AuditEntry
from kingsec.domain.identifiers import AuthorizationGrantId


class RevokeAuthorizationGrant:
    """Revoke an AuthorizationGrant, stamped at the current UTC time."""

    def __init__(
        self,
        grants: AuthorizationGrantRepository,
        audit: AuditPublisher | None = None,
    ) -> None:
        self._grants = grants
        self._audit = audit

    def execute(self, request: RevokeAuthorizationGrantRequest) -> RevokeAuthorizationGrantResponse:
        grant_id = AuthorizationGrantId(request.grant_id)
        # get() raises AuthorizationGrantNotFoundError for an unknown id -
        # never revoke a row that was never there.
        self._grants.get(grant_id)

        revoked_at = datetime.now(UTC)
        self._grants.revoke(grant_id, revoked_at)

        self._publish_audit(
            AuditEntry(
                action=AuditAction.AUTHORIZATION_GRANT_REVOKED,
                resource_type="authorization_grant",
                resource_id=grant_id.value,
                success=True,
                username=request.revoked_by,
                metadata={"revoked_at": revoked_at.isoformat()},
            )
        )

        return RevokeAuthorizationGrantResponse(grant_id=grant_id.value, revoked_at=revoked_at.isoformat())

    def _publish_audit(self, entry: AuditEntry) -> None:
        """Publish an audit entry if a publisher is configured (best-effort)."""
        if self._audit is None:
            return
        try:
            self._audit.record(entry)
        except Exception as exc:
            logging.getLogger(__name__).warning("audit publish failed (best-effort): %s", exc)
