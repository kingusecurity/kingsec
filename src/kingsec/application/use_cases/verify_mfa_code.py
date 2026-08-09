"""Use case: complete a pending login with a TOTP code and issue JWT."""

from __future__ import annotations

import logging

from kingsec.application.errors import ApplicationError
from kingsec.application.ports import AuditPublisher, TokenService, UserRepository
from kingsec.application.ports.outbound.audit_event_repository import AuditEventRepository
from kingsec.application.ports.outbound.mfa_secret_repository import MfaSecretRepository
from kingsec.application.ports.outbound.token_service import TokenError
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
    """Complete a pending login with a TOTP code and issue JWT tokens.

    This is the second step of the MFA-aware login flow: Login issues a
    short-lived pending token once the password (and lockout/active-account
    checks) have passed; this use case verifies that token plus a TOTP code
    and only then issues real access/refresh tokens. It never accepts a
    username/password directly - the pending token is the only proof of the
    first factor this use case will accept.
    """

    def __init__(
        self,
        users: UserRepository,
        tokens: TokenService,
        secret_repo: MfaSecretRepository,
        totp_service: TotpServicePort,
        legacy_audit: AuditPublisher | None = None,
        audit_repo: AuditEventRepository | None = None,
    ) -> None:
        self._users = users
        self._tokens = tokens
        self._secret_repo = secret_repo
        self._totp_service = totp_service
        self._legacy_audit = legacy_audit
        self._audit_repo = audit_repo

    def execute(self, request: VerifyMfaCodeRequest) -> VerifyMfaCodeResponse:
        import uuid
        from datetime import UTC, datetime

        # Step 1: Verify the pending token - this is the only accepted proof
        # that password/lockout/active-account checks already passed. Its
        # distinct JWT type means it can't be an access/refresh token
        # someone already had; a malformed, expired, or already-used
        # (revoked) pending token is rejected exactly like any other invalid
        # token, with the same generic message as a bad password would get.
        try:
            claims = self._tokens.verify_mfa_pending_token(request.pending_token)
        except TokenError:
            raise ApplicationError("invalid or expired login attempt; please sign in again") from None

        # Step 2: Look up the user the pending token identifies.
        user = self._users.find_by_id(claims.user_id)
        if user is None:
            raise ApplicationError("invalid or expired login attempt; please sign in again")

        # Step 3: Check account active. (Defense in depth against a TOCTOU
        # race - the account could theoretically be disabled in the short
        # window the pending token is valid for.)
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

        # Step 6: Issue tokens, and revoke the pending token so it can't be
        # used a second time (single-use, even within its 5-minute expiry).
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
        except Exception as exc:
            logging.getLogger(__name__).warning("audit publish failed (best-effort): %s", exc)

    def _publish_event(self, event: AuditEvent) -> None:
        if self._audit_repo is None:
            return
        try:
            self._audit_repo.save(event)
        except Exception as exc:
            logging.getLogger(__name__).warning("audit save failed (best-effort): %s", exc)
