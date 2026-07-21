"""Rate-limit domain model: key types, groups, and rate-limit configuration."""

from __future__ import annotations

from dataclasses import dataclass
from enum import StrEnum


class RateLimitKeyType(StrEnum):
    IP = "ip"
    USER = "user"
    API_KEY = "api_key"
    ENDPOINT = "endpoint"
    IP_USER = "ip_user"


class RateLimitGroup(StrEnum):
    LOGIN = "login"
    API = "api"
    SCAN = "scan"
    REPORT = "report"
    REFRESH_TOKEN = "refresh_token"  # nosec B105 — rate limit bucket name, not a credential
    PASSWORD_CHANGE = "password_change"  # nosec B105 — rate limit bucket name, not a credential
    MFA_VERIFY = "mfa_verify"
    API_KEY = "api_key"


@dataclass(frozen=True)
class RateLimitPolicy:
    group: RateLimitGroup
    max_requests: int
    window_seconds: int
    key_type: RateLimitKeyType = RateLimitKeyType.IP


@dataclass(frozen=True)
class RateLimitBucket:
    key: str
    max_requests: int
    window_seconds: int
    window_start: float
    count: int


@dataclass(frozen=True)
class RateLimitDecision:
    allowed: bool
    limit: int
    remaining: int
    reset_seconds: int


class RateLimitExceeded(Exception):
    def __init__(self, decision: RateLimitDecision) -> None:
        self.decision = decision
        super().__init__("rate limit exceeded")


@dataclass(frozen=True)
class LockoutPolicy:
    max_attempts: int
    lockout_duration_seconds: int


@dataclass(frozen=True)
class AccountLockout:
    user_id: str
    locked_until: float
    failed_attempts: int
