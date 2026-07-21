"""Use case: revoke (delete) an API key."""

from __future__ import annotations

from kingsec.application.dto import RevokeApiKeyRequest
from kingsec.application.errors import ApplicationError
from kingsec.application.ports import ApiKeyRepository


class RevokeApiKey:
    """Revoke an API key by marking it as revoked."""

    def __init__(self, repo: ApiKeyRepository) -> None:
        self._repo = repo

    def execute(self, request: RevokeApiKeyRequest) -> None:
        key = self._repo.find_by_id(request.api_key_id)
        if key is None:
            raise ApiKeyNotFoundError(request.api_key_id)

        if key.user_id != request.requesting_user_id:
            raise ApiKeyUnauthorizedError(f"user {request.requesting_user_id} does not own key {request.api_key_id}")

        key.revoke()
        self._repo.save(key)


class ApiKeyNotFoundError(ApplicationError):
    """Raised when an API key is not found."""

    def __init__(self, api_key_id: str) -> None:
        super().__init__(f"API key not found: {api_key_id}")
        self.api_key_id = api_key_id


class ApiKeyUnauthorizedError(ApplicationError):
    """Raised when a user tries to act on another user's key."""
