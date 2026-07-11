"""Use case: register a new user.

Steps:
    1. Validate the password meets complexity requirements.
    2. Check that the username is not already taken.
    3. Check that the email is not already registered.
    4. Hash the password.
    5. Create the user entity.
    6. Persist the user.

Security considerations:
    - Passwords are hashed before storage (never stored in plaintext).
    - Default role is "viewer" (least privilege).
    - Duplicate username/email are rejected with generic messages.
"""

from __future__ import annotations

from kingsec.domain import Role, User
from kingsec.domain.user import PasswordValidationError

from ..dto import RegisterUserRequest, RegisterUserResponse
from ..ports import PasswordHasher, UserRepository
from ..errors import ApplicationError


class RegisterUser:
    """Register a new user in the system."""

    def __init__(
        self,
        users: UserRepository,
        hasher: PasswordHasher,
    ) -> None:
        self._users = users
        self._hasher = hasher

    def execute(self, request: RegisterUserRequest) -> RegisterUserResponse:
        # Step 1: Validate password.
        self._validate_password(request.password)

        # Step 2: Check username uniqueness.
        if self._users.exists_by_username(request.username):
            raise RegistrationError("username already taken")

        # Step 3: Check email uniqueness.
        if self._users.exists_by_email(request.email):
            raise RegistrationError("email already registered")

        # Step 4: Hash the password.
        password_hash = self._hasher.hash(request.password)

        # Step 5: Parse role.
        try:
            role = Role[request.role.upper()]
        except KeyError:
            raise RegistrationError(f"invalid role: {request.role}")

        # Step 6: Create the user entity.
        import uuid
        user = User(
            id=str(uuid.uuid4()),
            username=request.username,
            email=request.email,
            password_hash=password_hash,
            role=role,
        )

        # Step 7: Persist.
        self._users.save(user)

        return RegisterUserResponse(
            user_id=user.id,
            username=user.username,
            email=user.email,
            role=user.role.label,
        )

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
