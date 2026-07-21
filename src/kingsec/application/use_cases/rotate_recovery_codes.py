"""Use case: rotate (replace) recovery codes for a user."""

from __future__ import annotations

from kingsec.application.ports.outbound.audit_event_repository import AuditEventRepository
from kingsec.application.ports.outbound.recovery_code_repository import RecoveryCodeRepository
from kingsec.domain.audit_event import (
    AuditAction,
    AuditEvent,
    AuditEventId,
    AuditOutcome,
    AuditSeverity,
)
from kingsec.domain.mfa import MfaRecoveryCode, RecoveryCodeStatus

from .mfa_dto import RotateRecoveryCodesRequest, RotateRecoveryCodesResponse


class RotateRecoveryCodes:
    """Replace all existing recovery codes with new ones."""

    def __init__(
        self,
        recovery_repo: RecoveryCodeRepository,
        audit_repo: AuditEventRepository | None = None,
    ) -> None:
        self._recovery_repo = recovery_repo
        self._audit_repo = audit_repo

    def execute(self, request: RotateRecoveryCodesRequest) -> RotateRecoveryCodesResponse:
        import hashlib
        import os
        import uuid
        from datetime import UTC, datetime

        plaintext_codes: list[str] = []
        hashed_codes: list[MfaRecoveryCode] = []

        for _ in range(10):
            code = f"{os.urandom(10).hex()}-{os.urandom(10).hex()}"
            plaintext_codes.append(code)
            code_hash = hashlib.sha256(code.encode()).hexdigest()
            hashed_codes.append(MfaRecoveryCode(code_hash=code_hash, status=RecoveryCodeStatus.ACTIVE))

        self._recovery_repo.save_batch(request.user_id, hashed_codes)

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
                message="Recovery codes rotated",
            )
            self._audit_repo.save(event)

        return RotateRecoveryCodesResponse(codes=tuple(plaintext_codes))
