"""Use case: authenticate with password + recovery code when MFA device is lost."""
from __future__ import annotations

import hashlib

from kingsec.domain.audit import AuditAction as LegacyAuditAction, AuditEntry
from kingsec.domain.audit_event import AuditAction, AuditEvent, AuditEventId, AuditOutcome, AuditSeverity

from ..errors import ApplicationError
from ..ports import AuditPublisher, PasswordHasher, TokenService, UserRepository
from ..ports.outbound.audit_event_repository import AuditEventRepository
from ..ports.outbound.mfa_secret_repository import MfaSecretRepository
from ..ports.outbound.recovery_code_repository import RecoveryCodeRepository
from .mfa_dto import UseRecoveryCodeRequest, UseRecoveryCodeResponse


class UseRecoveryCode:
    """Authenticate using username + password + recovery code."""

    def __init__(
        self,
        users: UserRepository,
        hasher: PasswordHasher,
        tokens: TokenService,
        secret_repo: MfaSecretRepository,
        recovery_repo: RecoveryCodeRepository,
        legacy_audit: AuditPublisher | None = None,
        audit_repo: AuditEventRepository | None = None,
    ) -> None:
        self._users = users
        self._hasher = hasher
        self._tokens = tokens
        self._secret_repo = secret_repo
        self._recovery_repo = recovery_repo
        self._legacy_audit = legacy_audit
        self._audit_repo = audit_repo

    def execute(self, request: UseRecoveryCodeRequest) -> UseRecoveryCodeResponse:
        import uuid
        from datetime import UTC, datetime

        user = self._users.find_by_username(request.username)
        if user is None:
            self._publish_legacy(AuditEntry(
                action=LegacyAuditAction.FAILED_LOGIN,
                resource_type="user",
                success=False,
                reason="invalid credentials",
                username=request.username,
            ))
            raise ApplicationError("invalid username or password")

        if not self._hasher.verify(request.password, user.password_hash):
            self._publish_legacy(AuditEntry(
                action=LegacyAuditAction.FAILED_LOGIN,
                resource_type="user",
                resource_id=user.id,
                success=False,
                reason="invalid credentials",
                user_id=user.id,
                username=user.username,
                role=user.role.label,
            ))
            raise ApplicationError("invalid username or password")

        if not user.is_active:
            raise ApplicationError("account is disabled")

        mfa_secret = self._secret_repo.find_by_user_id(user.id)
        if mfa_secret is None or mfa_secret.status.value != "enabled":
            raise ApplicationError("MFA is not enabled for this user")

        # Verify recovery code.
        input_hash = hashlib.sha256(request.recovery_code.encode()).hexdigest()
        recovery_codes = self._recovery_repo.find_by_user_id(user.id)
        matched = False
        for rc in recovery_codes:
            if rc.status.value == "used":
                continue
            if rc.code_hash == input_hash:
                self._recovery_repo.mark_used(user.id, rc.code_hash)
                matched = True
                break

        if not matched:
            self._publish_event(AuditEvent(
                id=AuditEventId(str(uuid.uuid4())),
                timestamp=datetime.now(UTC).isoformat(),
                actor_id=user.id,
                actor_type="user",
                username=user.username,
                ip_address="",
                user_agent="",
                request_id="",
                action=AuditAction.AUTHENTICATION_FAILURE,
                resource_type="mfa",
                resource_id=user.id,
                outcome=AuditOutcome.FAILURE,
                severity=AuditSeverity.WARNING,
                message="Invalid or used recovery code",
            ))
            raise ApplicationError("invalid recovery code")

        access_token = self._tokens.create_access_token(
            user_id=user.id, username=user.username, role=user.role.label,
        )
        refresh_token = self._tokens.create_refresh_token(
            user_id=user.id, username=user.username, role=user.role.label,
        )
        user.record_login()
        self._users.save(user)

        self._publish_legacy(AuditEntry(
            action=LegacyAuditAction.LOGIN,
            resource_type="user",
            resource_id=user.id,
            success=True,
            user_id=user.id,
            username=user.username,
            role=user.role.label,
        ))
        self._publish_event(AuditEvent(
            id=AuditEventId(str(uuid.uuid4())),
            timestamp=datetime.now(UTC).isoformat(),
            actor_id=user.id,
            actor_type="user",
            username=user.username,
            ip_address="",
            user_agent="",
            request_id="",
            action=AuditAction.LOGIN_SUCCESS,
            resource_type="mfa",
            resource_id=user.id,
            outcome=AuditOutcome.SUCCESS,
            severity=AuditSeverity.INFO,
            message="Recovery code used for login",
        ))

        return UseRecoveryCodeResponse(
            user_id=user.id,
            username=user.username,
            role=user.role.label,
            access_token=access_token,
            refresh_token=refresh_token,
        )

    def _publish_legacy(self, entry: AuditEntry) -> None:
        if self._legacy_audit is None:
            return
        try:
            self._legacy_audit.record(entry)
        except Exception:
            pass

    def _publish_event(self, event: AuditEvent) -> None:
        if self._audit_repo is None:
            return
        try:
            self._audit_repo.save(event)
        except Exception:
            pass
