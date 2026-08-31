"""Port for user persistence — application layer contract.

The ``UserRepository`` port defines how the application retrieves and stores
User entities. Infrastructure implements this port; the application never
knows about SQLAlchemy, databases, or storage mechanics.

Design decisions:
    - find_by_username: primary lookup for authentication (case-insensitive).
    - find_by_id: lookup for current-user resolution.
    - save: create or update a user.
    - exists_by_username: duplicate-check during user creation.
    - list_all: admin user management (with pagination).
"""

from __future__ import annotations

from abc import ABC, abstractmethod

from kingsec.domain import Role
from kingsec.domain.user import User


class UserRepository(ABC):
    """Abstract port for user persistence."""

    @abstractmethod
    def find_by_username(self, username: str) -> User | None:
        """Find a user by username (case-insensitive).

        Args:
            username: The login name to look up.

        Returns:
            The User if found, None otherwise.
        """

    @abstractmethod
    def find_by_id(self, user_id: str) -> User | None:
        """Find a user by their unique ID.

        Args:
            user_id: The UUID string to look up.

        Returns:
            The User if found, None otherwise.
        """

    @abstractmethod
    def save(self, user: User) -> None:
        """Create or update a user.

        Args:
            user: The user entity to persist.
        """

    @abstractmethod
    def save_new_user_claiming_bootstrap_admin(self, user: User) -> User:
        """Insert a brand-new user, atomically claiming the one-time
        first-user-becomes-admin bootstrap slot.

        KSEC-73-05: ``user.role`` is used as given UNLESS this call is the
        one that inserts the very first row this table has ever had, in
        which case the persisted role is ``Role.ADMIN`` regardless of
        ``user.role`` - decided by a single atomic database operation
        (not a separate "count users" read followed by a later insert),
        so that under two concurrent registrations against an empty
        table, at most one can ever win the bootstrap-admin claim.

        Only ever call this for a genuinely new user (this is not an
        upsert - use ``save`` for updates to an existing user).

        Returns:
            The User exactly as persisted, with ``role`` reflecting
            whichever outcome the atomic claim actually produced.
        """

    @abstractmethod
    def exists_by_username(self, username: str) -> bool:
        """Check if a username is already taken.

        Args:
            username: The login name to check.

        Returns:
            True if a user with that username exists.
        """

    @abstractmethod
    def exists_by_email(self, email: str) -> bool:
        """Check if an email is already registered.

        Args:
            email: The email address to check.

        Returns:
            True if a user with that email exists.
        """

    @abstractmethod
    def list_all(self, limit: int = 50, offset: int = 0) -> list[User]:
        """List users with pagination.

        Args:
            limit: Maximum number of users to return.
            offset: Number of users to skip.

        Returns:
            List of User entities.
        """

    @abstractmethod
    def search(
        self,
        *,
        query: str | None = None,
        role: str | None = None,
        is_active: bool | None = None,
        limit: int = 50,
        offset: int = 0,
        order_by: str = "username",
        order_dir: str = "asc",
    ) -> tuple[list[User], int]:
        """Search users with filters, pagination, and sorting."""

    @abstractmethod
    def count(self) -> int:
        """Return the total number of users."""

    @abstractmethod
    def count_by_role(self, role: Role) -> int:
        """Return the number of users with a given role.

        Args:
            role: The Role to count.

        Returns:
            Number of users with that role.
        """
