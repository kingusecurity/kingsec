"""Use case: change a user's password.

Steps:
    1. Look up the user by ID.
    2. Verify the current password.
    3. Validate the new password meets complexity requirements.
    4. Hash the new password.
    5. Update the user entity.
    6. Persist the changes.
    7. Revoke every outstanding session/token for this user (KSEC-73-01).
    8. Publish audit entry.

Security considerations:
    - Current password verification prevents unauthorized changes.
    - New password must meet complexity requirements.
    - Passwords are hashed before storage.
    - A successful password change revokes every session/token issued
      before it, using the same RevokeAllSessions mechanism the
      explicit "log out everywhere" feature already uses - a stolen
      access/refresh token from before the change stops authenticating
      immediately, not merely at its own natural expiry.
    - Audit entries record password changes for security monitoring.
"""

from __future__ import annotations

import logging

from kingsec.application.dto import ChangePasswordRequest
from kingsec.application.errors import ApplicationError
from kingsec.application.ports import AuditPublisher, PasswordHasher, UserRepository
from kingsec.application.use_cases.revoke_all_sessions import RevokeAllSessions
from kingsec.application.use_cases.session_dto import RevokeAllSessionsRequest
from kingsec.domain.audit import AuditAction, AuditEntry


class ChangePassword:
    """Change a user's password."""

    def __init__(
        self,
        users: UserRepository,
        hasher: PasswordHasher,
        sessions: RevokeAllSessions,
        audit: AuditPublisher | None = None,
    ) -> None:
        self._users = users
        self._hasher = hasher
        self._sessions = sessions
        self._audit = audit

    def execute(self, request: ChangePasswordRequest) -> None:
        # Step 1: Look up the user.
        user = self._users.find_by_id(request.user_id)
        if user is None:
            raise PasswordChangeError("user not found")

        # Step 2: Verify current password.
        if not self._hasher.verify(request.current_password, user.password_hash):
            raise PasswordChangeError("current password is incorrect")

        # Step 3: Validate new password.
        self._validate_password(request.new_password)

        # Step 4: Hash the new password.
        user.password_hash = self._hasher.hash(request.new_password)

        # Step 5: Persist.
        self._users.save(user)

        # Step 6: KSEC-73-01 - revoke every outstanding session/token for
        # this user. Reuses RevokeAllSessions exactly as the explicit
        # "log out everywhere" feature does, rather than a second,
        # parallel revocation mechanism.
        self._sessions.execute(RevokeAllSessionsRequest(user_id=user.id))

        # Step 7: Audit password change.
        self._publish_audit(
            AuditEntry(
                action=AuditAction.PASSWORD_CHANGED,
                resource_type="user",
                resource_id=user.id,
                success=True,
                user_id=user.id,
                username=user.username,
                role=user.role.label,
            )
        )

    def _publish_audit(self, entry: AuditEntry) -> None:
        """Publish an audit entry if a publisher is configured (best-effort)."""
        if self._audit is None:
            return
        try:
            self._audit.record(entry)
        except Exception as exc:
            logging.getLogger(__name__).warning("audit publish failed (best-effort): %s", exc)

    @staticmethod
    def _validate_password(password: str) -> None:
        """Validate password complexity."""
        if len(password) < 8:
            from kingsec.domain.user import PasswordValidationError

            raise PasswordValidationError("password must be at least 8 characters")
        if len(password) > 128:
            from kingsec.domain.user import PasswordValidationError

            raise PasswordValidationError("password must be at most 128 characters")
        if not any(c.isupper() for c in password):
            from kingsec.domain.user import PasswordValidationError

            raise PasswordValidationError("password must contain an uppercase letter")
        if not any(c.islower() for c in password):
            from kingsec.domain.user import PasswordValidationError

            raise PasswordValidationError("password must contain a lowercase letter")
        if not any(c.isdigit() for c in password):
            from kingsec.domain.user import PasswordValidationError

            raise PasswordValidationError("password must contain a digit")


class PasswordChangeError(ApplicationError):
    """Raised when password change fails."""
