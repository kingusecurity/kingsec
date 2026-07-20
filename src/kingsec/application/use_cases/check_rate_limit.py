from __future__ import annotations

from kingsec.application.ports.outbound.rate_limiter import RateLimiterPort
from kingsec.application.use_cases.rate_limit_dto import (
    CheckRateLimitRequest,
    CheckRateLimitResponse,
)
from kingsec.domain.rate_limit import RateLimitExceeded


class CheckRateLimit:
    def __init__(self, rate_limiter: RateLimiterPort) -> None:
        self._rate_limiter = rate_limiter

    def execute(self, request: CheckRateLimitRequest) -> CheckRateLimitResponse:
        decision = self._rate_limiter.check(request.key, request.policy)

        if not decision.allowed:
            raise RateLimitExceeded(decision)

        self._rate_limiter.record(request.key, request.policy)

        return CheckRateLimitResponse(
            allowed=decision.allowed,
            limit=decision.limit,
            remaining=decision.remaining,
            reset_seconds=decision.reset_seconds,
        )
