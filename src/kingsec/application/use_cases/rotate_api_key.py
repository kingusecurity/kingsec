"""Use case: rotate an API key (replace with a new key)."""

from __future__ import annotations

import secrets

from kingsec.domain.api_key import ApiKeyStatus

from ..dto import RotateApiKeyRequest, RotateApiKeyResponse
from ..ports import ApiKeyHasher, ApiKeyRepository

from .revoke_api_key import ApiKeyNotFoundError, ApiKeyUnauthorizedError


class RotateApiKey:
    """Rotate an API key — generate a new key, update the stored hash."""

    def __init__(self, repo: ApiKeyRepository, hasher: ApiKeyHasher) -> None:
        self._repo = repo
        self._hasher = hasher

    def execute(self, request: RotateApiKeyRequest) -> RotateApiKeyResponse:
        key = self._repo.find_by_id(request.api_key_id)
        if key is None:
            raise ApiKeyNotFoundError(request.api_key_id)

        if key.user_id != request.requesting_user_id:
            raise ApiKeyUnauthorizedError(
                f"user {request.requesting_user_id} does not own key {request.api_key_id}"
            )

        plaintext = f"ks_{key.id}_{secrets.token_urlsafe(40)}"
        key.key_hash = self._hasher.hash(plaintext)
        key.status = ApiKeyStatus.ACTIVE
        key.last_used_at = None

        self._repo.save(key)

        return RotateApiKeyResponse(
            api_key_id=key.id,
            name=key.name,
            plaintext_key=plaintext,
            scope=key.scope.value,
            created_at=key.created_at.isoformat(),
        )
