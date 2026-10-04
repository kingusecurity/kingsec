"""Use case: register a new user.

Steps:
    0. Refuse if self-registration is disabled (SecuritySettings.
       allow_self_registration, default False - Phase 3, auth hardening).
    1. Validate the password meets complexity requirements.
    2. Check that the username is not already taken.
    3. Check that the email is not already registered.
    4. Hash the password.
    5. Build the user entity with the default role (VIEWER).
    6. Persist via UserRepository.save_new_user.
    7. Publish audit entry.

Security considerations:
    - Passwords are hashed before storage (never stored in plaintext).
    - Default role is "viewer" (least privilege) for every self-registered
      user, including the first. Phase 3 (auth hardening) removed the old
      KSEC-73-05 "first user becomes ADMIN" bootstrap grant entirely: an
      unauthenticated caller who won the race to be first through this
      endpoint on a network-reachable instance could permanently own the
      system. The initial admin is now created ONLY by `kingsec-bootstrap`
      (src/kingsec/_bootstrap.py), an operator-invoked CLI requiring an
      explicit credential, never this HTTP endpoint.
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
        allow_self_registration: bool = True,
    ) -> None:
        # `allow_self_registration` defaults to True here (test/construction
        # convenience, same shape as `license_gate: ... | None = None`
        # meaning "no limit unless a caller asks for one") - the real,
        # secure-by-default value (SecuritySettings.allow_self_registration
        # = False) is what bootstrap/composition.py's DI factory actually
        # passes in production. ~30 existing call sites across unrelated
        # test files (RBAC, MFA, audit-events, worker-routes-authorization,
        # etc.) construct `RegisterUser(user_repo, hasher)` purely as setup
        # for a feature they're not testing; defaulting this to False here
        # would break all of them for something out of this phase's scope.
        self._users = users
        self._hasher = hasher
        self._audit = audit
        self._license_gate = license_gate
        self._allow_self_registration = allow_self_registration

    def execute(self, request: RegisterUserRequest) -> RegisterUserResponse:
        # Step -1 (Phase 3, auth hardening): self-registration is OFF by
        # default (SecuritySettings.allow_self_registration). When
        # disabled, refuse before any other check - never let a caller
        # learn about the license limit, uniqueness, etc. for a path that
        # is closed regardless. The message differs depending on whether
        # an administrator exists yet, so an operator reading their own
        # logs can act without reading source (Phase 3 requirement):
        #   - no admin yet: point at kingsec-bootstrap, the only path that
        #     can create one.
        #   - an admin already exists: name the setting that would
        #     re-enable this endpoint.
        if not self._allow_self_registration:
            if self._users.count_by_role(Role.ADMIN) == 0:
                raise RegistrationDisabledError(
                    "no administrator exists yet; run kingsec-bootstrap to initialize this instance"
                )
            raise RegistrationDisabledError(
                "self-registration is disabled; set KINGSEC_SECURITY__ALLOW_SELF_REGISTRATION=true "
                "to enable it, or contact an administrator"
            )

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

        # Step 5: Build the user entity with the default role (VIEWER).
        # Phase 3: never overridden to ADMIN by the repository anymore -
        # see save_new_user_claiming_bootstrap_admin's removal, below.
        import uuid

        user = User(
            id=str(uuid.uuid4()),
            username=request.username,
            email=request.email,
            password_hash=password_hash,
            role=Role.VIEWER,
        )

        # Step 6: Persist. Use the value actually persisted, not `user`,
        # for symmetry with the pre-Phase-3 code this replaces (the role
        # is no longer overridden, but the persisted row is still the
        # source of truth for the response/audit entry below).
        persisted = self._users.save_new_user(user)

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


class RegistrationDisabledError(ApplicationError):
    """Raised when self-registration is disabled (SecuritySettings.
    allow_self_registration = False, the default since Phase 3). Never
    raised for any other reason - the message itself already tells the
    caller exactly what to do (run kingsec-bootstrap, or set the env var),
    so no separate error code branching is needed at the call site."""
