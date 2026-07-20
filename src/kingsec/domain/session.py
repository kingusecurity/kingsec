from __future__ import annotations

from dataclasses import dataclass, field
from datetime import UTC, datetime
from enum import Enum
from uuid import uuid4


class SessionStatus(str, Enum):
    ACTIVE = "active"
    REVOKED = "revoked"
    EXPIRED = "expired"


class SessionType(str, Enum):
    USER = "user"
    API_KEY = "api_key"


@dataclass(frozen=True)
class SessionId:
    value: str

    def __str__(self) -> str:
        return self.value

    @classmethod
    def generate(cls) -> SessionId:
        return cls(value=uuid4().hex)


@dataclass(frozen=True)
class DeviceInfo:
    device_name: str = ""
    platform: str = ""
    browser: str = ""


@dataclass(frozen=True)
class Session:
    id: SessionId
    user_id: str
    session_type: SessionType
    jti: str
    refresh_jti: str
    issued_at: str
    expires_at: str
    last_activity: str
    client_ip: str
    user_agent: str
    device_info: DeviceInfo = field(default_factory=DeviceInfo)
    status: SessionStatus = SessionStatus.ACTIVE
    idle_timeout_seconds: int = 1800

    def is_active(self) -> bool:
        return self.status == SessionStatus.ACTIVE

    def is_expired(self, now_iso: str) -> bool:
        return now_iso >= self.expires_at

    def is_idle(self, now_iso: str) -> bool:
        if self.idle_timeout_seconds <= 0:
            return False
        last = datetime.fromisoformat(self.last_activity)
        now = datetime.fromisoformat(now_iso)
        elapsed = (now - last).total_seconds()
        return elapsed > self.idle_timeout_seconds
