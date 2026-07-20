"""Use case: disable MFA (TOTP) for a user."""
from __future__ import annotations

from kingsec.domain.audit_event import AuditAction, AuditEvent, AuditEventId, AuditOutcome, AuditSeverity

from ..ports.outbound.audit_event_repository import AuditEventRepository
from ..ports.outbound.mfa_secret_repository import MfaSecretRepository
from ..ports.outbound.recovery_code_repository import RecoveryCodeRepository
from .mfa_dto import DisableMfaRequest


class DisableMfa:
    """Disable MFA for a user and remove all associated data."""

    def __init__(
        self,
        secret_repo: MfaSecretRepository,
        recovery_repo: RecoveryCodeRepository,
        audit_repo: AuditEventRepository | None = None,
    ) -> None:
        self._secret_repo = secret_repo
        self._recovery_repo = recovery_repo
        self._audit_repo = audit_repo

    def execute(self, request: DisableMfaRequest) -> None:
        import uuid
        from datetime import UTC, datetime

        self._secret_repo.delete_by_user_id(request.user_id)
        self._recovery_repo.delete_by_user_id(request.user_id)

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
                message="MFA disabled",
            )
            self._audit_repo.save(event)
