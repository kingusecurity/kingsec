from __future__ import annotations

from dataclasses import dataclass

from kingsec.domain.rate_limit import RateLimitPolicy


@dataclass(frozen=True)
class CheckRateLimitRequest:
    key: str
    policy: RateLimitPolicy


@dataclass(frozen=True)
class CheckRateLimitResponse:
    allowed: bool
    limit: int
    remaining: int
    reset_seconds: int


@dataclass(frozen=True)
class RecordFailedAuthenticationRequest:
    user_id: str
    ip_address: str
    username: str


@dataclass(frozen=True)
class RecordFailedAuthenticationResponse:
    locked: bool
    locked_until: float | None
    failed_attempts: int


@dataclass(frozen=True)
class RecordSuccessfulAuthenticationRequest:
    user_id: str


@dataclass(frozen=True)
class RecordSuccessfulAuthenticationResponse:
    previous_failed_attempts: int


@dataclass(frozen=True)
class CheckAccountLockoutRequest:
    user_id: str


@dataclass(frozen=True)
class CheckAccountLockoutResponse:
    locked: bool
    locked_until: float | None
    failed_attempts: int


@dataclass(frozen=True)
class ResetFailedAttemptsRequest:
    user_id: str


@dataclass(frozen=True)
class ResetFailedAttemptsResponse:
    success: bool
