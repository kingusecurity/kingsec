"""Use case: register a new user.

Steps:
    1. Validate the password meets complexity requirements.
    2. Check that the username is not already taken.
    3. Check that the email is not already registered.
    4. Hash the password.
    5. Build the user entity with the non-bootstrap default role.
    6. Persist, atomically claiming the first-user-becomes-admin
       bootstrap slot if this is the very first user the table has
       ever had.
    7. Publish audit entry.

Security considerations:
    - Passwords are hashed before storage (never stored in plaintext).
    - Default role is "viewer" (least privilege) for all users except
      the very first one, which becomes ADMIN to bootstrap the system.
    - KSEC-73-05: the first-user-admin decision is made by a single
      atomic database operation (UserRepository.
      save_new_user_claiming_bootstrap_admin), not a separate "count
      users" read followed by a later insert - two concurrent
      registrations against an empty database cannot both win the
      bootstrap-admin claim.
    - Duplicate username/email are rejected with generic messages.
    - Audit entries record registration attempts for security monitoring.
"""

from __future__ import annotations

import logging

from kingsec.application.dto import RegisterUserRequest, RegisterUserResponse
from kingsec.application.errors import ApplicationError, LicenseRequiredError
from kingsec.application.ports import AuditPublisher, PasswordHasher, UserRepository
from kingsec.application.services.licensing import LicenseGate
from kingsec.domain import Role, User
from kingsec.domain.audit import AuditAction, AuditEntry
from kingsec.domain.user import PasswordValidationError


class RegisterUser:
    """Register a new user in the system."""

    def __init__(
        self,
        users: UserRepository,
        hasher: PasswordHasher,
        audit: AuditPublisher | None = None,
        license_gate: LicenseGate | None = None,
    ) -> None:
        self._users = users
        self._hasher = hasher
        self._audit = audit
        self._license_gate = license_gate

    def execute(self, request: RegisterUserRequest) -> RegisterUserResponse:
        # Step 0: Enforce the installation-wide user limit (server-side
        # count, never client-supplied). `max_users() is None` means
        # unlimited (Professional/Enterprise). The numeric limit alone is
        # authoritative here - Phase 82 established there is no separate
        # "can register users at all" boolean, unlike api_keys.
        if self._license_gate is not None:
            limit = self._license_gate.max_users()
            if limit is not None and self._users.count() >= limit:
                raise LicenseRequiredError(
                    f"Users (limit of {limit} reached)",
                    self._license_gate.current_edition().value,
                    required="an edition with a higher user limit",
                )

        # Step 1: Validate password.
        self._validate_password(request.password)

        # Step 2: Check username uniqueness.
        # Step 3: Check email uniqueness.
        # KSEC-86-03 (registration enumeration, carried forward from Phase
        # 84): both checks raise the SAME message. Previously "username
        # already taken" vs. "email already registered" let an
        # unauthenticated caller submit a guessed email with a fresh random
        # username and learn, from the response body alone, whether an
        # account exists for that email - a classic account-enumeration
        # oracle. login.py already treats the equivalent case this way
        # ("invalid username or password" for both "no such user" and
        # "wrong password"); this matches that established convention.
        if self._users.exists_by_username(request.username) or self._users.exists_by_email(request.email):
            raise RegistrationError("username or email already in use")

        # Step 4: Hash the password.
        password_hash = self._hasher.hash(request.password)

        # Step 5: Build the user entity with the non-bootstrap default
        # role (VIEWER) - the repository may atomically override this to
        # ADMIN if this call turns out to be the very first user.
        import uuid

        user = User(
            id=str(uuid.uuid4()),
            username=request.username,
            email=request.email,
            password_hash=password_hash,
            role=Role.VIEWER,
        )

        # Step 6: Persist, atomically claiming the bootstrap-admin slot
        # (KSEC-73-05). Use the value actually persisted, not `user`,
        # since the role may have been overridden.
        persisted = self._users.save_new_user_claiming_bootstrap_admin(user)

        # Step 7: Audit successful registration.
        self._publish_audit(
            AuditEntry(
                action=AuditAction.USER_REGISTERED,
                resource_type="user",
                resource_id=persisted.id,
                success=True,
                user_id=persisted.id,
                username=persisted.username,
                role=persisted.role.label,
            )
        )

        return RegisterUserResponse(
            user_id=persisted.id,
            username=persisted.username,
            email=persisted.email,
            role=persisted.role.label,
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
            raise PasswordValidationError("password must be at least 8 characters")
        if len(password) > 128:
            raise PasswordValidationError("password must be at most 128 characters")
        if not any(c.isupper() for c in password):
            raise PasswordValidationError("password must contain an uppercase letter")
        if not any(c.islower() for c in password):
            raise PasswordValidationError("password must contain a lowercase letter")
        if not any(c.isdigit() for c in password):
            raise PasswordValidationError("password must contain a digit")


class RegistrationError(ApplicationError):
    """Raised when user registration fails."""
