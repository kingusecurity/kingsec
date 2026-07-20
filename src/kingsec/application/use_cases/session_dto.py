from __future__ import annotations

from dataclasses import dataclass, field

from kingsec.domain.session import DeviceInfo, SessionType


@dataclass(frozen=True)
class SessionView:
    id: str
    user_id: str
    session_type: str
    jti: str
    issued_at: str
    expires_at: str
    last_activity: str
    client_ip: str
    user_agent: str
    device_name: str
    platform: str
    browser: str
    status: str


@dataclass(frozen=True)
class CreateSessionRequest:
    user_id: str
    jti: str
    refresh_jti: str
    client_ip: str
    user_agent: str
    device_info: DeviceInfo = field(default_factory=DeviceInfo)
    session_type: SessionType = SessionType.USER


@dataclass(frozen=True)
class CreateSessionResponse:
    session_id: str


@dataclass(frozen=True)
class ValidateSessionRequest:
    jti: str
    user_id: str


@dataclass(frozen=True)
class ValidateSessionResponse:
    valid: bool
    session_id: str | None


@dataclass(frozen=True)
class RefreshSessionRequest:
    user_id: str
    old_refresh_jti: str
    new_refresh_jti: str
    new_access_jti: str


@dataclass(frozen=True)
class RefreshSessionResponse:
    valid: bool
    replay_detected: bool


@dataclass(frozen=True)
class RevokeSessionRequest:
    session_id: str


@dataclass(frozen=True)
class RevokeSessionResponse:
    success: bool


@dataclass(frozen=True)
class RevokeAllSessionsRequest:
    user_id: str
    exclude_session_id: str | None = None


@dataclass(frozen=True)
class RevokeAllSessionsResponse:
    revoked_count: int


@dataclass(frozen=True)
class ListUserSessionsRequest:
    user_id: str


@dataclass(frozen=True)
class ListUserSessionsResponse:
    sessions: list[SessionView]


@dataclass(frozen=True)
class TerminateOtherSessionsRequest:
    user_id: str
    current_session_id: str


@dataclass(frozen=True)
class TerminateOtherSessionsResponse:
    terminated_count: int
