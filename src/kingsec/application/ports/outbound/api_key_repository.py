"""Port for API key persistence — application layer contract.

The ``ApiKeyRepository`` port defines how the application stores and retrieves
API key entities. Infrastructure implements this port; the application never
knows about SQLAlchemy, databases, or storage mechanics.
"""

from __future__ import annotations

from abc import ABC, abstractmethod

from kingsec.domain.api_key import ApiKey


class ApiKeyRepository(ABC):
    """Abstract port for API key persistence."""

    @abstractmethod
    def find_by_id(self, api_key_id: str) -> ApiKey | None:
        """Find an API key by its unique ID.

        Args:
            api_key_id: The UUID string to look up.

        Returns:
            The ApiKey if found, None otherwise.
        """

    @abstractmethod
    def find_by_user_id(self, user_id: str, limit: int = 50, offset: int = 0) -> list[ApiKey]:
        """List API keys owned by a user (paginated).

        Args:
            user_id: The owning user's ID.
            limit: Maximum number of keys to return.
            offset: Number of keys to skip.

        Returns:
            List of ApiKey entities.
        """

    @abstractmethod
    def save(self, key: ApiKey) -> None:
        """Create or update an API key.

        Args:
            key: The ApiKey entity to persist.
        """

    @abstractmethod
    def delete(self, api_key_id: str) -> None:
        """Permanently delete an API key.

        Args:
            api_key_id: The UUID string of the key to delete.
        """

    @abstractmethod
    def count_by_user(self, user_id: str) -> int:
        """Return the total number of API keys for a user.

        Args:
            user_id: The owning user's ID.

        Returns:
            Total key count.
        """

    @abstractmethod
    def count_all(self) -> int:
        """Return the total number of API keys across the whole installation.

        Used to enforce the license edition's installation-wide
        ``max_api_keys`` limit, which is not per-user.

        Returns:
            Total key count across all users.
        """
