"""Use case: complete a pending login with a recovery code (MFA device lost)."""

from __future__ import annotations

import hashlib
import logging

from kingsec.application.errors import ApplicationError
from kingsec.application.ports import AuditPublisher, TokenService, UserRepository
from kingsec.application.ports.outbound.audit_event_repository import AuditEventRepository
from kingsec.application.ports.outbound.mfa_secret_repository import MfaSecretRepository
from kingsec.application.ports.outbound.recovery_code_repository import RecoveryCodeRepository
from kingsec.application.ports.outbound.token_service import TokenError
from kingsec.domain.audit import AuditAction as LegacyAuditAction
from kingsec.domain.audit import AuditEntry
from kingsec.domain.audit_event import (
    AuditAction,
    AuditEvent,
    AuditEventId,
    AuditOutcome,
    AuditSeverity,
)

from .mfa_dto import UseRecoveryCodeRequest, UseRecoveryCodeResponse


class UseRecoveryCode:
    """Complete a pending login with a recovery code, when the MFA device is lost.

    Second step of the MFA-aware login flow, same shape as VerifyMfaCode but
    for the "lost my authenticator" path: Login issues a pending token after
    password/lockout/active-account checks pass; this use case verifies that
    token plus a recovery code and only then issues real tokens.
    """

    def __init__(
        self,
        users: UserRepository,
        tokens: TokenService,
        secret_repo: MfaSecretRepository,
        recovery_repo: RecoveryCodeRepository,
        legacy_audit: AuditPublisher | None = None,
        audit_repo: AuditEventRepository | None = None,
    ) -> None:
        self._users = users
        self._tokens = tokens
        self._secret_repo = secret_repo
        self._recovery_repo = recovery_repo
        self._legacy_audit = legacy_audit
        self._audit_repo = audit_repo

    def execute(self, request: UseRecoveryCodeRequest) -> UseRecoveryCodeResponse:
        import uuid
        from datetime import UTC, datetime

        try:
            claims = self._tokens.verify_mfa_pending_token(request.pending_token)
        except TokenError:
            raise ApplicationError("invalid or expired login attempt; please sign in again") from None

        user = self._users.find_by_id(claims.user_id)
        if user is None:
            raise ApplicationError("invalid or expired login attempt; please sign in again")

        if not user.is_active:
            raise ApplicationError("account is disabled")

        mfa_secret = self._secret_repo.find_by_user_id(user.id)
        if mfa_secret is None or mfa_secret.status.value != "enabled":
            raise ApplicationError("MFA is not enabled for this user")

        # KSEC-73-04: attempt the atomic ACTIVE -> USED transition
        # directly, rather than reading all codes first and deciding
        # in-process which one to mark - that read-then-write shape is
        # exactly the TOCTOU window this fix closes. mark_used()'s own
        # WHERE clause (code_hash matches AND status='active') is the
        # only place "does this code exist, is it unused, and does it
        # match" is decided, atomically, at the database.
        input_hash = hashlib.sha256(request.recovery_code.encode()).hexdigest()
        matched = self._recovery_repo.mark_used(user.id, input_hash)

        if not matched:
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
                    message="Invalid or used recovery code",
                )
            )
            raise ApplicationError("invalid recovery code")

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
        self._tokens.revoke_token(claims.jti)
        user.record_login()
        self._users.save(user)

        self._publish_legacy(
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
                message="Recovery code used for login",
            )
        )

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
        except Exception as exc:
            logging.getLogger(__name__).warning("audit publish failed (best-effort): %s", exc)

    def _publish_event(self, event: AuditEvent) -> None:
        if self._audit_repo is None:
            return
        try:
            self._audit_repo.save(event)
        except Exception as exc:
            logging.getLogger(__name__).warning("audit save failed (best-effort): %s", exc)
