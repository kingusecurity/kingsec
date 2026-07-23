from __future__ import annotations

from kingsec.application.ports import TokenService
from kingsec.application.ports.outbound.session_repository import SessionRepository
from kingsec.application.use_cases.session_dto import (
    RevokeAllSessionsRequest,
    RevokeAllSessionsResponse,
)


class RevokeAllSessions:
    def __init__(self, repo: SessionRepository, tokens: TokenService) -> None:
        self._repo = repo
        self._tokens = tokens

    def execute(self, request: RevokeAllSessionsRequest) -> RevokeAllSessionsResponse:
        active = self._repo.find_active_by_user(request.user_id)
        count = len(active)
        for s in active:
            if request.exclude_session_id and str(s.id) == request.exclude_session_id:
                continue
            self._tokens.revoke_token(s.jti)
            self._tokens.revoke_token(s.refresh_jti)
        self._repo.revoke_all_by_user(request.user_id, exclude_session_id=request.exclude_session_id)
        return RevokeAllSessionsResponse(revoked_count=count)
