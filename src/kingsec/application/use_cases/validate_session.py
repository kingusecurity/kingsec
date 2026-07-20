from __future__ import annotations

from datetime import UTC, datetime

from kingsec.application.ports.outbound.clock_port import ClockPort
from kingsec.application.ports.outbound.session_repository import SessionRepository
from kingsec.application.use_cases.session_dto import (
    ValidateSessionRequest,
    ValidateSessionResponse,
)


class ValidateSession:
    def __init__(self, repo: SessionRepository, clock: ClockPort) -> None:
        self._repo = repo
        self._clock = clock

    def execute(self, request: ValidateSessionRequest) -> ValidateSessionResponse:
        session = self._repo.find_by_jti(request.jti)
        if session is None:
            return ValidateSessionResponse(valid=False, session_id=None)

        if session.status.value != "active":
            return ValidateSessionResponse(valid=False, session_id=None)

        now_iso = datetime.fromtimestamp(self._clock.now(), tz=UTC).isoformat()
        if now_iso >= session.expires_at:
            return ValidateSessionResponse(valid=False, session_id=None)

        self._repo.update_activity(str(session.id), now_iso)

        return ValidateSessionResponse(
            valid=True,
            session_id=str(session.id),
        )
