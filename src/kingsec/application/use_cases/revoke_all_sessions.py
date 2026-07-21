from __future__ import annotations

from kingsec.application.ports.outbound.session_repository import SessionRepository
from kingsec.application.use_cases.session_dto import (
    RevokeAllSessionsRequest,
    RevokeAllSessionsResponse,
)


class RevokeAllSessions:
    def __init__(self, repo: SessionRepository) -> None:
        self._repo = repo

    def execute(self, request: RevokeAllSessionsRequest) -> RevokeAllSessionsResponse:
        active = self._repo.find_active_by_user(request.user_id)
        count = len(active)
        self._repo.revoke_all_by_user(request.user_id, exclude_session_id=request.exclude_session_id)
        return RevokeAllSessionsResponse(revoked_count=count)
