"""Use case: enable MFA (TOTP) for a user."""
from __future__ import annotations

from kingsec.application.ports.outbound.audit_event_repository import AuditEventRepository
from kingsec.application.ports.outbound.mfa_secret_repository import MfaSecretRepository
from kingsec.application.ports.outbound.totp_service import TotpServicePort
from kingsec.domain.audit_event import (
    AuditAction,
    AuditEvent,
    AuditEventId,
    AuditOutcome,
    AuditSeverity,
)
from kingsec.domain.mfa import MfaSecret, MfaStatus

from .mfa_dto import EnableMfaRequest, EnableMfaResponse


class EnableMfa:
    """Generate a TOTP secret and enable MFA for a user."""

    def __init__(
        self,
        secret_repo: MfaSecretRepository,
        totp_service: TotpServicePort,
        audit_repo: AuditEventRepository | None = None,
    ) -> None:
        self._secret_repo = secret_repo
        self._totp_service = totp_service
        self._audit_repo = audit_repo

    def execute(self, request: EnableMfaRequest) -> EnableMfaResponse:
        import uuid
        from datetime import UTC, datetime

        secret = self._totp_service.generate_secret()
        uri = self._totp_service.generate_uri(secret, request.user_id)
        mfa_secret = MfaSecret(user_id=request.user_id, secret_key=secret, status=MfaStatus.ENABLED)
        self._secret_repo.save(mfa_secret)

        if self._audit_repo:
            event = AuditEvent(
                id=AuditEventId(str(uuid.uuid4())),
                timestamp=datetime.now(UTC).isoformat(),
                actor_id=request.user_id,
                actor_type="user",
                username="",
                ip_address="",
                user_agent="",
                request_id="",
                action=AuditAction.PASSWORD_CHANGED,
                resource_type="mfa",
                resource_id=request.user_id,
                outcome=AuditOutcome.SUCCESS,
                severity=AuditSeverity.INFO,
                message="MFA enabled",
            )
            self._audit_repo.save(event)

        return EnableMfaResponse(secret=secret, uri=uri)
