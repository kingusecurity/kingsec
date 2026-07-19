"""User domain entity — pure business model, no framework dependencies.

The User entity represents an authenticated identity in the system. It carries
business rules for:
    - Password validation (minimum length, complexity)
    - Active/inactive status
    - Role-based permission checks
    - Last login tracking

Design decisions:
    - The password hash is stored as a string value; hashing/verification is
      an application-layer concern (PasswordHasher port).
    - The entity is mutable (users can change roles, update last login).
    - User IDs are UUID strings for consistency with Assessment/Finding IDs.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import UTC, datetime

from .enums import Role
from .errors import DomainError, InvariantViolation


class UserError(DomainError):
    """Base error for user-related domain violations."""


class UserNotFoundError(UserError):
    """Raised when a user lookup fails."""

    def __init__(self, identifier: str) -> None:
        super().__init__(f"user not found: {identifier}")
        self.context: dict[str, str] = {"identifier": identifier}


class InvalidCredentialsError(UserError):
    """Raised when authentication fails (wrong username or password)."""

    def __init__(self) -> None:
        super().__init__("invalid username or password")


class UserDisabledError(UserError):
    """Raised when a disabled user attempts to authenticate."""

    def __init__(self, username: str) -> None:
        super().__init__(f"account disabled: {username}")
        self.context: dict[str, str] = {"username": username}


class PasswordValidationError(UserError):
    """Raised when a password fails validation rules."""

    def __init__(self, reason: str) -> None:
        super().__init__(f"password validation failed: {reason}")


@dataclass
class User:
    """User entity with identity and business rules.

    Attributes:
        id: Unique identifier (UUID string).
        username: Unique, case-insensitive login name.
        email: Unique email address.
        password_hash: Hashed password (set at creation, updated on change).
        role: User role determining permission level.
        is_active: Whether the account is enabled.
        created_at: Account creation timestamp (UTC).
        last_login_at: Most recent successful login timestamp (UTC).
    """

    id: str
    username: str
    email: str
    password_hash: str
    role: Role
    is_active: bool = True
    created_at: datetime = field(default_factory=lambda: datetime.now(UTC))
    last_login_at: datetime | None = None

    def __post_init__(self) -> None:
        """Validate invariants after construction."""
        self._validate_username(self.username)
        self._validate_email(self.email)

    @staticmethod
    def _validate_username(username: str) -> None:
        """Username must be non-empty and alphanumeric with underscores."""
        if not username or not username.strip():
            raise InvariantViolation("username must not be empty")
        if len(username) < 3:
            raise InvariantViolation("username must be at least 3 characters")
        if len(username) > 64:
            raise InvariantViolation("username must be at most 64 characters")
        if not all(c.isalnum() or c == "_" for c in username):
            raise InvariantViolation(
                "username must contain only alphanumeric characters and underscores"
            )

    @staticmethod
    def _validate_email(email: str) -> None:
        """Basic email format validation."""
        if not email or not email.strip():
            raise InvariantViolation("email must not be empty")
        if "@" not in email:
            raise InvariantViolation("email must contain @")
        if len(email) > 254:
            raise InvariantViolation("email must be at most 254 characters")

    def record_login(self) -> None:
        """Record a successful login timestamp."""
        self.last_login_at = datetime.now(UTC)

    def disable(self) -> None:
        """Disable the user account."""
        self.is_active = False

    def enable(self) -> None:
        """Enable the user account."""
        self.is_active = True

    def change_role(self, new_role: Role) -> None:
        """Change the user's role."""
        self.role = new_role

    def can(self, required_role: Role) -> bool:
        """Check if this user has at least the required role level."""
        if not self.is_active:
            return False
        return self.role.has_permission(required_role)
