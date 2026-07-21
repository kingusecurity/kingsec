"""Use case: authenticate with password + TOTP code and issue JWT."""

from __future__ import annotations

from kingsec.application.errors import ApplicationError
from kingsec.application.ports import AuditPublisher, PasswordHasher, TokenService, UserRepository
from kingsec.application.ports.outbound.audit_event_repository import AuditEventRepository
from kingsec.application.ports.outbound.mfa_secret_repository import MfaSecretRepository
from kingsec.application.ports.outbound.totp_service import TotpServicePort
from kingsec.domain.audit import AuditAction as LegacyAuditAction
from kingsec.domain.audit import AuditEntry
from kingsec.domain.audit_event import (
    AuditAction,
    AuditEvent,
    AuditEventId,
    AuditOutcome,
    AuditSeverity,
)

from .mfa_dto import VerifyMfaCodeRequest, VerifyMfaCodeResponse


class VerifyMfaCode:
    """Verify password + TOTP code and issue JWT tokens.

    This is the MFA-aware login flow. The user must provide valid credentials
    AND a valid TOTP code. If MFA is not enabled for the user, authentication
    will fail (they should use the standard login endpoint instead).
    """

    def __init__(
        self,
        users: UserRepository,
        hasher: PasswordHasher,
        tokens: TokenService,
        secret_repo: MfaSecretRepository,
        totp_service: TotpServicePort,
        legacy_audit: AuditPublisher | None = None,
        audit_repo: AuditEventRepository | None = None,
    ) -> None:
        self._users = users
        self._hasher = hasher
        self._tokens = tokens
        self._secret_repo = secret_repo
        self._totp_service = totp_service
        self._legacy_audit = legacy_audit
        self._audit_repo = audit_repo

    def execute(self, request: VerifyMfaCodeRequest) -> VerifyMfaCodeResponse:
        import uuid
        from datetime import UTC, datetime

        # Step 1: Look up user.
        user = self._users.find_by_username(request.username)
        if user is None:
            self._publish_legacy_audit(
                AuditEntry(
                    action=LegacyAuditAction.FAILED_LOGIN,
                    resource_type="user",
                    success=False,
                    reason="invalid credentials",
                    username=request.username,
                )
            )
            raise ApplicationError("invalid username or password")

        # Step 2: Verify password.
        if not self._hasher.verify(request.password, user.password_hash):
            self._publish_legacy_audit(
                AuditEntry(
                    action=LegacyAuditAction.FAILED_LOGIN,
                    resource_type="user",
                    resource_id=user.id,
                    success=False,
                    reason="invalid credentials",
                    user_id=user.id,
                    username=user.username,
                    role=user.role.label,
                )
            )
            raise ApplicationError("invalid username or password")

        # Step 3: Check account active.
        if not user.is_active:
            raise ApplicationError("account is disabled")

        # Step 4: Check MFA is enabled.
        mfa_secret = self._secret_repo.find_by_user_id(user.id)
        if mfa_secret is None or mfa_secret.status.value != "enabled":
            self._publish_event(
                AuditEvent(
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
                    message="MFA not enabled for user",
                )
            )
            raise ApplicationError("MFA is not enabled for this user")

        # Step 5: Verify TOTP code.
        if not self._totp_service.verify(mfa_secret.secret_key, request.totp_code):
            self._publish_event(
                AuditEvent(
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
                    message="Invalid TOTP code",
                )
            )
            raise ApplicationError("invalid TOTP code")

        # Step 6: Issue tokens.
        access_token = self._tokens.create_access_token(
            user_id=user.id,
            username=user.username,
            role=user.role.label,
        )
        refresh_token = self._tokens.create_refresh_token(
            user_id=user.id,
            username=user.username,
            role=user.role.label,
        )
        user.record_login()
        self._users.save(user)

        # Step 7: Audit success.
        self._publish_legacy_audit(
            AuditEntry(
                action=LegacyAuditAction.LOGIN,
                resource_type="user",
                resource_id=user.id,
                success=True,
                user_id=user.id,
                username=user.username,
                role=user.role.label,
            )
        )
        self._publish_event(
            AuditEvent(
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
                message="MFA verification successful",
            )
        )

        return VerifyMfaCodeResponse(
            user_id=user.id,
            username=user.username,
            role=user.role.label,
            access_token=access_token,
            refresh_token=refresh_token,
        )

    def _publish_legacy_audit(self, entry: AuditEntry) -> None:
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
