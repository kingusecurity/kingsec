from __future__ import annotations

from datetime import UTC, datetime

from kingsec.application.ports import TokenService
from kingsec.application.ports.outbound.session_repository import SessionRepository
from kingsec.application.use_cases.session_dto import (
    RefreshSessionRequest,
    RefreshSessionResponse,
)


class RefreshSession:
    def __init__(self, repo: SessionRepository, tokens: TokenService) -> None:
        self._repo = repo
        self._tokens = tokens

    def execute(self, request: RefreshSessionRequest) -> RefreshSessionResponse:
        active = self._repo.find_active_by_user(request.user_id)

        matching = [s for s in active if s.refresh_jti == request.old_refresh_jti]

        if matching:
            session = matching[0]
            self._tokens.revoke_token(session.refresh_jti)
            self._tokens.revoke_token(session.jti)
            self._repo.update_refresh_jti(str(session.id), request.new_refresh_jti)
            self._repo.update_access_jti(str(session.id), request.new_access_jti)
            now_iso = datetime.fromtimestamp(datetime.now(UTC).timestamp(), tz=UTC).isoformat()
            self._repo.update_activity(str(session.id), now_iso)
            return RefreshSessionResponse(valid=True, replay_detected=False)

        if active:
            for s in active:
                self._tokens.revoke_token(s.jti)
                self._tokens.revoke_token(s.refresh_jti)
            self._repo.revoke_all_by_user(request.user_id)
            return RefreshSessionResponse(valid=False, replay_detected=True)

        return RefreshSessionResponse(valid=False, replay_detected=False)
