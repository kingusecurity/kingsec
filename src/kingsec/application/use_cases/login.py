"""Use case: authenticate a user and issue tokens.

Steps:
    1. Look up the user by username.
    2. Check whether the account is currently locked out from prior failed
       attempts.
    3. Verify the password against the stored hash.
    4. On a locked account or a wrong password: record the failure (which
       may itself trigger a new lockout) and reject with the exact same
       generic error either way.
    5. Check that the account is active.
    6. Record the successful authentication (clears any lockout state).
    7. Generate access and refresh tokens.
    8. Record the login timestamp.
    9. Publish audit entry (success or failure).

Security considerations:
    - Password verification uses constant-time comparison (via PasswordHasher).
    - Invalid credentials produce a generic error message (no username enumeration).
    - A locked account gets the exact same treatment: the real password hash
      is still checked (so response timing doesn't differ from an ordinary
      wrong-password check), and the same generic error is raised regardless
      of whether the password was actually correct — a locked account cannot
      be distinguished from a wrong-password attempt by message or timing.
      This matches the existing nonexistent-user dummy-hash pattern's care
      level; the lockout state itself is only ever visible in the audit log
      (see reason="account is locked"), never in the response.
    - Disabled accounts are rejected with a specific error — this one IS
      intentionally distinguishable from a wrong password (existing,
      unchanged behavior; lockout deliberately does not follow this example).
    - Audit entries record both successes and failures for security monitoring.
"""

from __future__ import annotations

import logging

from kingsec.application.dto import LoginRequest, LoginResponse
from kingsec.application.errors import ApplicationError
from kingsec.application.ports import AuditPublisher, PasswordHasher, TokenService, UserRepository
from kingsec.application.ports.outbound.clock_port import ClockPort
from kingsec.application.ports.outbound.lockout_repository import LockoutRepository
from kingsec.application.use_cases.check_account_lockout import CheckAccountLockout
from kingsec.application.use_cases.rate_limit_dto import (
    CheckAccountLockoutRequest,
    RecordFailedAuthenticationRequest,
    RecordSuccessfulAuthenticationRequest,
)
from kingsec.application.use_cases.record_failed_authentication import RecordFailedAuthentication
from kingsec.application.use_cases.record_successful_authentication import RecordSuccessfulAuthentication
from kingsec.domain.audit import AuditAction, AuditEntry
from kingsec.domain.rate_limit import LockoutPolicy


class Login:
    """Authenticate a user and issue JWT tokens."""

    def __init__(
        self,
        users: UserRepository,
        hasher: PasswordHasher,
        tokens: TokenService,
        lockout_repo: LockoutRepository,
        clock: ClockPort,
        lockout_policy: LockoutPolicy,
        audit: AuditPublisher | None = None,
    ) -> None:
        self._users = users
        self._hasher = hasher
        self._tokens = tokens
        self._audit = audit
        # Sub-use-cases built from the injected ports, same shape as e.g.
        # NotificationService building MarkNotificationRead from its own
        # injected repo — Login depends on ports, not pre-built use-case
        # instances, matching its existing constructor style.
        self._check_lockout = CheckAccountLockout(lockout_repo, clock)
        self._record_failed = RecordFailedAuthentication(
            lockout_repo,
            clock,
            max_attempts=lockout_policy.max_attempts,
            lockout_duration_seconds=lockout_policy.lockout_duration_seconds,
        )
        self._record_success = RecordSuccessfulAuthentication(lockout_repo)
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

        # Step 2: Check lockout, and Step 3: verify the password — always
        # both, always in this order, regardless of the lockout outcome.
        # Running the real hash comparison even when already locked keeps
        # this branch's timing identical to an ordinary wrong-password
        # check; deciding the outcome from `locked OR not password_ok`
        # means a correct password against a locked account still fails,
        # and both cases raise the exact same generic error below.
        lockout_status = self._check_lockout.execute(CheckAccountLockoutRequest(user_id=user.id))
        password_ok = self._hasher.verify(request.password, user.password_hash)

        # Step 4: on lockout or wrong password, record the failure and
        # reject — same generic error either way.
        if lockout_status.locked or not password_ok:
            self._record_failed.execute(
                RecordFailedAuthenticationRequest(user_id=user.id, ip_address="", username=user.username)
            )
            self._publish_audit(
                AuditEntry(
                    action=AuditAction.FAILED_LOGIN,
                    resource_type="user",
                    resource_id=user.id,
                    success=False,
                    reason="account is locked" if lockout_status.locked else "invalid username or password",
                    user_id=user.id,
                    username=user.username,
                    role=user.role.label,
                )
            )
            raise AuthenticationError("invalid username or password")

        # Step 5: Check that the account is active.
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

        # Step 6: Record the successful authentication (clears any lockout).
        self._record_success.execute(RecordSuccessfulAuthenticationRequest(user_id=user.id))

        # Step 7: Generate tokens.
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

        # Step 8: Record login.
        user.record_login()
        self._users.save(user)

        # Step 9: Audit successful login.
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
