from __future__ import annotations

from kingsec.application.ports import TokenService
from kingsec.application.ports.outbound.session_repository import SessionRepository
from kingsec.application.use_cases.session_dto import (
    RevokeSessionRequest,
    RevokeSessionResponse,
)


class RevokeSession:
    def __init__(self, repo: SessionRepository, tokens: TokenService) -> None:
        self._repo = repo
        self._tokens = tokens

    def execute(self, request: RevokeSessionRequest) -> RevokeSessionResponse:
        existing = self._repo.find_by_id(request.session_id)
        if existing is None:
            return RevokeSessionResponse(success=False)
        self._tokens.revoke_token(existing.jti)
        self._tokens.revoke_token(existing.refresh_jti)
        self._repo.revoke(request.session_id)
        return RevokeSessionResponse(success=True)
