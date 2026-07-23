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
