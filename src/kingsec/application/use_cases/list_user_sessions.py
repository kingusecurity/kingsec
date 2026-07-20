from __future__ import annotations

from kingsec.application.ports.outbound.session_repository import SessionRepository
from kingsec.application.use_cases.session_dto import (
    ListUserSessionsRequest,
    ListUserSessionsResponse,
    SessionView,
)


class ListUserSessions:
    def __init__(self, repo: SessionRepository) -> None:
        self._repo = repo

    def execute(self, request: ListUserSessionsRequest) -> ListUserSessionsResponse:
        sessions = self._repo.find_active_by_user(request.user_id)
        views = [
            SessionView(
                id=str(s.id),
                user_id=s.user_id,
                session_type=s.session_type.value,
                jti=s.jti,
                issued_at=s.issued_at,
                expires_at=s.expires_at,
                last_activity=s.last_activity,
                client_ip=s.client_ip,
                user_agent=s.user_agent,
                device_name=s.device_info.device_name,
                platform=s.device_info.platform,
                browser=s.device_info.browser,
                status=s.status.value,
            )
            for s in sessions
        ]
        return ListUserSessionsResponse(sessions=views)
