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
        # check() and record() are two separate, non-atomic calls - safe today
        # only because every caller in this codebase reaches here through an
        # `async def` chain with no `await` between check() and record(), so
        # a single-process uvicorn event loop can't interleave another
        # request's check() in between. The interface itself does not
        # guarantee atomicity: this would need a real fix (e.g. a combined
        # check-and-record operation under one lock) before ever running
        # multi-worker/multi-process, or before swapping the backend for
        # something with a genuine `await` point (e.g. Redis).
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
