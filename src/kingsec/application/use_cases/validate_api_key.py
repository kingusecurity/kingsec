"""Use case: validate a full API key token against its stored hash."""

from __future__ import annotations

from kingsec.application.dto import ValidateApiKeyRequest, ValidateApiKeyResponse
from kingsec.application.errors import ApplicationError
from kingsec.application.ports import ApiKeyHasher, ApiKeyRepository

from .revoke_api_key import ApiKeyNotFoundError


def _parse_api_key(api_key: str) -> str:
    """Extract the key ID from a ``ks_<uuid>_<secret>`` token.

    Returns the UUID portion, or raises ValueError if the format is invalid.
    """
    if not api_key.startswith("ks_"):
        raise ValueError("API key must start with 'ks_'")
    parts = api_key.split("_", 2)
    if len(parts) < 3:
        raise ValueError("API key format: ks_<uuid>_<secret>")
    return parts[1]


class ValidateApiKey:
    """Validate a full API key token."""

    def __init__(self, repo: ApiKeyRepository, hasher: ApiKeyHasher) -> None:
        self._repo = repo
        self._hasher = hasher

    def execute(self, request: ValidateApiKeyRequest) -> ValidateApiKeyResponse:
        try:
            key_id = _parse_api_key(request.api_key)
        except ValueError as exc:
            raise ApplicationError(str(exc)) from exc

        key = self._repo.find_by_id(key_id)
        if key is None:
            raise ApiKeyNotFoundError(key_id)

        if not key.status.is_active:
            raise ApplicationError(f"API key is {key.status.value}")

        if not self._hasher.verify(request.api_key, key.key_hash):
            raise ApplicationError("API key hash mismatch")

        key.record_usage()
        self._repo.save(key)

        return ValidateApiKeyResponse(
            api_key_id=key.id,
            user_id=key.user_id,
            scope=key.scope.value,
            status=key.status.value,
        )
