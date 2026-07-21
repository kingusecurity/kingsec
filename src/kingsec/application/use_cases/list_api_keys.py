"""Use case: list API keys for a user."""

from __future__ import annotations

from kingsec.application.dto import ApiKeyView, ListApiKeysRequest
from kingsec.application.ports import ApiKeyRepository


class ListApiKeys:
    """List API keys owned by a user."""

    def __init__(self, repo: ApiKeyRepository) -> None:
        self._repo = repo

    def execute(self, request: ListApiKeysRequest) -> tuple[ApiKeyView, ...]:
        keys = self._repo.find_by_user_id(
            request.user_id, limit=request.limit, offset=request.offset
        )
        return tuple(
            ApiKeyView(
                api_key_id=k.id,
                user_id=k.user_id,
                name=k.name,
                scope=k.scope.value,
                status=k.status.value,
                last_used_at=k.last_used_at.isoformat() if k.last_used_at else None,
                created_at=k.created_at.isoformat(),
            )
            for k in keys
        )
