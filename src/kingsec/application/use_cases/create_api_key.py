"""Use case: create a new API key."""

from __future__ import annotations

import secrets

from kingsec.domain.api_key import ApiKey, ApiKeyScope, ApiKeyStatus

from ..dto import CreateApiKeyRequest, CreateApiKeyResponse
from ..errors import ApplicationError
from ..ports import ApiKeyHasher, ApiKeyRepository


class CreateApiKey:
    """Create a new API key for programmatic access.

    The key is returned as ``ks_<uuid>_<secret>`` where the UUID is the key's
    database identifier. The full key is hashed before storage; the plaintext
    is returned once and cannot be recovered.
    """

    def __init__(self, repo: ApiKeyRepository, hasher: ApiKeyHasher) -> None:
        self._repo = repo
        self._hasher = hasher

    def execute(self, request: CreateApiKeyRequest) -> CreateApiKeyResponse:
        import uuid

        key_id = str(uuid.uuid4())
        secret = secrets.token_urlsafe(40)
        plaintext = f"ks_{key_id}_{secret}"

        try:
            scope = ApiKeyScope(request.scope)
        except ValueError:
            raise ApiKeyError(f"invalid scope: {request.scope}")

        key = ApiKey(
            id=key_id,
            user_id=request.user_id,
            name=request.name,
            key_hash=self._hasher.hash(plaintext),
            scope=scope,
            status=ApiKeyStatus.ACTIVE,
        )

        self._repo.save(key)

        return CreateApiKeyResponse(
            api_key_id=key.id,
            name=key.name,
            plaintext_key=plaintext,
            scope=key.scope.value,
            created_at=key.created_at.isoformat(),
        )


class ApiKeyError(ApplicationError):
    """Raised when an API key operation fails."""
