"""Use case: authenticate a user and issue tokens.

Steps:
    1. Look up the user by username.
    2. Verify the password against the stored hash.
    3. Check that the account is active.
    4. Generate access and refresh tokens.
    5. Record the login timestamp.
    6. Publish audit entry (success or failure).

Security considerations:
    - Password verification uses constant-time comparison (via PasswordHasher).
    - Invalid credentials produce a generic error message (no username enumeration).
    - Disabled accounts are rejected with a specific error.
    - Audit entries record both successes and failures for security monitoring.
"""

from __future__ import annotations

import logging

from kingsec.application.dto import LoginRequest, LoginResponse
from kingsec.application.errors import ApplicationError
from kingsec.application.ports import AuditPublisher, PasswordHasher, TokenService, UserRepository
from kingsec.domain.audit import AuditAction, AuditEntry


class Login:
    """Authenticate a user and issue JWT tokens."""

    def __init__(
        self,
        users: UserRepository,
        hasher: PasswordHasher,
        tokens: TokenService,
        audit: AuditPublisher | None = None,
    ) -> None:
        self._users = users
        self._hasher = hasher
        self._tokens = tokens
        self._audit = audit
        # Pre-compute a dummy hash so the "user not found" path takes the same
        # time as the real verification path, preventing timing-based enumeration.
        self._dummy_hash = hasher.hash("constant-time-dummy-password")

    def execute(self, request: LoginRequest) -> LoginResponse:
        # Step 1: Look up the user.
        user = self._users.find_by_username(request.username)
        if user is None:
            # Constant-time comparison: always hash to prevent timing-based
            # username enumeration.  The dummy verify runs the full KDF even
            # though the user doesn't exist, so the response timing is
            # indistinguishable from a real failed login.
            self._hasher.verify(request.password, self._dummy_hash)
            self._publish_audit(
                AuditEntry(
                    action=AuditAction.FAILED_LOGIN,
                    resource_type="user",
                    success=False,
                    reason="invalid username or password",
                    username=request.username,
                )
            )
            raise AuthenticationError("invalid username or password")

        # Step 2: Verify the password.
        if not self._hasher.verify(request.password, user.password_hash):
            self._publish_audit(
                AuditEntry(
                    action=AuditAction.FAILED_LOGIN,
                    resource_type="user",
                    resource_id=user.id,
                    success=False,
                    reason="invalid username or password",
                    user_id=user.id,
                    username=user.username,
                    role=user.role.label,
                )
            )
            raise AuthenticationError("invalid username or password")

        # Step 3: Check that the account is active.
        if not user.is_active:
            self._publish_audit(
                AuditEntry(
                    action=AuditAction.FAILED_LOGIN,
                    resource_type="user",
                    resource_id=user.id,
                    success=False,
                    reason="account is disabled",
                    user_id=user.id,
                    username=user.username,
                    role=user.role.label,
                )
            )
            raise AuthenticationError("account is disabled")

        # Step 4: Generate tokens.
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

        # Step 5: Record login.
        user.record_login()
        self._users.save(user)

        # Step 6: Audit successful login.
        self._publish_audit(
            AuditEntry(
                action=AuditAction.LOGIN,
                resource_type="user",
                resource_id=user.id,
                success=True,
                user_id=user.id,
                username=user.username,
                role=user.role.label,
            )
        )

        return LoginResponse(
            user_id=user.id,
            username=user.username,
            role=user.role.label,
            access_token=access_token,
            refresh_token=refresh_token,
        )

    def _publish_audit(self, entry: AuditEntry) -> None:
        """Publish an audit entry if a publisher is configured (best-effort)."""
        if self._audit is None:
            return
        try:
            self._audit.record(entry)
        except Exception as exc:
            logging.getLogger(__name__).warning("audit publish failed (best-effort): %s", exc)


class AuthenticationError(ApplicationError):
    """Raised when authentication fails."""
