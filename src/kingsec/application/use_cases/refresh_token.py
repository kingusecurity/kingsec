"""Use case: refresh an access token using a refresh token.

Steps:
    1. Verify the refresh token (check expiry, signature, type).
    2. Look up the user to ensure they still exist and are active.
    3. Generate a new access token.
    4. Optionally rotate the refresh token (security best practice).
    5. Publish audit entry.

Security considerations:
    - Refresh tokens are verified for type == "refresh" to prevent access
      token reuse.
    - User existence is checked to handle deleted/disabled accounts.
    - The old refresh token is not revoked (stateless refresh) for simplicity;
      add revocation for higher security requirements.
    - Audit entries record token refresh events for security monitoring.
"""

from __future__ import annotations

import logging

from kingsec.application.dto import RefreshTokenRequest, RefreshTokenResponse
from kingsec.application.errors import ApplicationError
from kingsec.application.ports import AuditPublisher, TokenService, UserRepository
from kingsec.domain.audit import AuditAction, AuditEntry


class RefreshToken:
    """Issue a new access token using a valid refresh token."""

    def __init__(
        self,
        users: UserRepository,
        tokens: TokenService,
        audit: AuditPublisher | None = None,
    ) -> None:
        self._users = users
        self._tokens = tokens
        self._audit = audit

    def execute(self, request: RefreshTokenRequest) -> RefreshTokenResponse:
        # Step 1: Verify the refresh token.
        try:
            claims = self._tokens.verify_refresh_token(request.refresh_token)
        except Exception as exc:
            raise TokenRefreshError("invalid or expired refresh token") from exc

        # Step 2: Verify the token type (prevent access token reuse).
        if claims.token_type != "refresh":  # nosec B105 — "refresh" is a JWT token type, not a credential
            raise TokenRefreshError("invalid token type")

        # Step 3: Look up the user to ensure they still exist and are active.
        user = self._users.find_by_id(claims.user_id)
        if user is None:
            raise TokenRefreshError("user not found")
        if not user.is_active:
            raise TokenRefreshError("account is disabled")

        # Step 4: Generate a new access token.
        access_token = self._tokens.create_access_token(
            user_id=user.id,
            username=user.username,
            role=user.role.label,
        )

        # Step 5: Audit token refresh.
        self._publish_audit(
            AuditEntry(
                action=AuditAction.TOKEN_REFRESHED,
                resource_type="user",
                resource_id=user.id,
                success=True,
                user_id=user.id,
                username=user.username,
                role=user.role.label,
            )
        )

        return RefreshTokenResponse(access_token=access_token)

    def _publish_audit(self, entry: AuditEntry) -> None:
        """Publish an audit entry if a publisher is configured (best-effort)."""
        if self._audit is None:
            return
        try:
            self._audit.record(entry)
        except Exception as exc:
            logging.getLogger(__name__).warning("audit publish failed (best-effort): %s", exc)


class TokenRefreshError(ApplicationError):
    """Raised when token refresh fails."""
