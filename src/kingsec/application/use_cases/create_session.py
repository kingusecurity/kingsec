from __future__ import annotations

from datetime import UTC, datetime, timedelta

from kingsec.application.ports import TokenService
from kingsec.application.ports.outbound.clock_port import ClockPort
from kingsec.application.ports.outbound.session_repository import SessionRepository
from kingsec.application.use_cases.session_dto import (
    CreateSessionRequest,
    CreateSessionResponse,
)
from kingsec.domain.session import (
    Session,
    SessionId,
    SessionStatus,
)


class CreateSession:
    def __init__(
        self,
        repo: SessionRepository,
        clock: ClockPort,
        tokens: TokenService,
        max_concurrent_sessions: int = 5,
        session_ttl_seconds: int = 604800,
        idle_timeout_seconds: int = 1800,
    ) -> None:
        self._repo = repo
        self._clock = clock
        self._tokens = tokens
        self._max_concurrent = max_concurrent_sessions
        self._session_ttl = session_ttl_seconds
        self._idle_timeout = idle_timeout_seconds

    def execute(self, request: CreateSessionRequest) -> CreateSessionResponse:
        now_ts = self._clock.now()
        now_iso = datetime.fromtimestamp(now_ts, tz=UTC).isoformat()
        expires_iso = (datetime.fromtimestamp(now_ts, tz=UTC) + timedelta(seconds=self._session_ttl)).isoformat()

        active_count = self._repo.count_active_by_user(request.user_id)
        if active_count >= self._max_concurrent:
            oldest = self._repo.find_active_by_user(request.user_id)
            if oldest:
                oldest_sorted = sorted(oldest, key=lambda s: s.issued_at)
                evicted = oldest_sorted[0]
                # KSEC-73-02: revoke the evicted session's JWTs, not just
                # its Session row - mirrors RevokeSession's exact pattern
                # so an evicted device's tokens stop authenticating
                # immediately instead of surviving until natural expiry.
                self._tokens.revoke_token(evicted.jti)
                self._tokens.revoke_token(evicted.refresh_jti)
                self._repo.revoke(evicted.id.value)

        session = Session(
            id=SessionId.generate(),
            user_id=request.user_id,
            session_type=request.session_type,
            jti=request.jti,
            refresh_jti=request.refresh_jti,
            issued_at=now_iso,
            expires_at=expires_iso,
            last_activity=now_iso,
            client_ip=request.client_ip,
            user_agent=request.user_agent,
            device_info=request.device_info,
            status=SessionStatus.ACTIVE,
            idle_timeout_seconds=self._idle_timeout,
        )
        self._repo.save(session)
        return CreateSessionResponse(session_id=str(session.id))
