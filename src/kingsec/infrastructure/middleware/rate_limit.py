"""Per-IP rate limiting middleware.

Uses a token bucket algorithm for rate limiting. Each client IP gets its
own bucket. Separate limits for authentication endpoints and general
API endpoints.

Design decisions:
    - Token bucket allows bursts up to ``burst_size`` while enforcing
      sustained rate limits.
    - Auth endpoints (login, register) have stricter limits to prevent
      brute-force attacks.
    - The middleware is stateful (in-memory) — suitable for single-process
      deployments. For multi-process, swap the bucket store for Redis.
    - Rate limit headers (X-RateLimit-Limit, X-RateLimit-Remaining,
      X-RateLimit-Reset) are included in every response.
"""

from __future__ import annotations

import threading
import time
from collections import defaultdict
from typing import Any

from starlette.middleware.base import BaseHTTPMiddleware, RequestResponseEndpoint
from starlette.requests import Request
from starlette.responses import JSONResponse, Response

from kingsec.infrastructure.config.models import RateLimitSettings
from kingsec.infrastructure.logging import get_logger


class _TokenBucket:
    """A single token bucket for rate limiting."""

    __slots__ = ("capacity", "last_refill", "refill_rate", "tokens")

    def __init__(self, capacity: int, refill_rate: float) -> None:
        self.capacity = capacity
        self.tokens = float(capacity)
        self.refill_rate = refill_rate  # tokens per second
        self.last_refill = time.monotonic()

    def consume(self) -> bool:
        """Try to consume one token. Returns True if allowed."""
        now = time.monotonic()
        elapsed = now - self.last_refill
        self.tokens = min(self.capacity, self.tokens + elapsed * self.refill_rate)
        self.last_refill = now

        if self.tokens >= 1.0:
            self.tokens -= 1.0
            return True
        return False

    @property
    def reset_seconds(self) -> float:
        """Time until the next token is available."""
        if self.tokens >= 1.0:
            return 0.0
        return (1.0 - self.tokens) / self.refill_rate

    @property
    def is_idle(self) -> bool:
        """True if the bucket is at full capacity (no recent activity)."""
        return self.tokens >= self.capacity


class RateLimitMiddleware(BaseHTTPMiddleware):
    """Middleware that enforces per-IP rate limits."""

    # Paths that use the stricter auth rate limit.
    # MFA verify and recovery are unauthenticated (the caller hasn't completed
    # auth yet), so they need the same brute-force protection as login.
    _AUTH_PATHS = frozenset(
        {
            "/api/v1/auth/login",
            "/api/v1/auth/register",
            "/api/v1/mfa/verify",
            "/api/v1/mfa/recovery",
        }
    )

    # Evict idle buckets every N dispatches to prevent unbounded memory growth.
    _EVICTION_INTERVAL = 1000
    _dispatch_counter: int = 0

    def __init__(self, app: Any, settings: RateLimitSettings) -> None:
        super().__init__(app)
        self._settings = settings
        self._buckets: dict[str, _TokenBucket] = defaultdict(self._make_bucket)
        self._auth_buckets: dict[str, _TokenBucket] = defaultdict(self._make_auth_bucket)
        self._lock = threading.Lock()
        self._logger = get_logger("kingsec.middleware.rate_limit")

    def _make_bucket(self) -> _TokenBucket:
        rate = self._settings.api_requests_per_minute / 60.0
        return _TokenBucket(
            capacity=self._settings.burst_size,
            refill_rate=rate,
        )

    def _make_auth_bucket(self) -> _TokenBucket:
        rate = self._settings.auth_requests_per_minute / 60.0
        return _TokenBucket(
            capacity=min(self._settings.burst_size, self._settings.auth_requests_per_minute),
            refill_rate=rate,
        )

    def _evict_idle(self) -> None:
        """Remove buckets that are at full capacity (no recent activity)."""
        before = len(self._buckets) + len(self._auth_buckets)
        self._buckets = defaultdict(
            self._make_bucket,
            {k: v for k, v in self._buckets.items() if not v.is_idle},
        )
        self._auth_buckets = defaultdict(
            self._make_auth_bucket,
            {k: v for k, v in self._auth_buckets.items() if not v.is_idle},
        )
        after = len(self._buckets) + len(self._auth_buckets)
        evicted = before - after
        if evicted:
            self._logger.debug("evicted %d idle rate-limit buckets", evicted)

    async def dispatch(self, request: Request, call_next: RequestResponseEndpoint) -> Response:
        if not self._settings.enabled:
            return await call_next(request)

        client_ip = request.client.host if request.client else "unknown"
        is_auth_path = request.url.path in self._AUTH_PATHS

        with self._lock:
            if is_auth_path:
                bucket = self._auth_buckets[client_ip]
                limit = self._settings.auth_requests_per_minute
            else:
                bucket = self._buckets[client_ip]
                limit = self._settings.api_requests_per_minute

            allowed = bucket.consume()
            remaining = max(0, int(bucket.tokens))
            reset_seconds = int(bucket.reset_seconds) + 1

            # Periodic eviction of idle buckets.
            type(self)._dispatch_counter += 1
            if self._dispatch_counter >= self._EVICTION_INTERVAL:
                self._dispatch_counter = 0
                self._evict_idle()

        if not allowed:
            return JSONResponse(
                status_code=429,
                content={
                    "error_code": "KS-RATE-001",
                    "message": "rate limit exceeded, try again later",
                },
                headers={
                    "X-RateLimit-Limit": str(limit),
                    "X-RateLimit-Remaining": "0",
                    "X-RateLimit-Reset": str(reset_seconds),
                    "Retry-After": str(reset_seconds),
                },
            )

        response = await call_next(request)
        response.headers["X-RateLimit-Limit"] = str(limit)
        response.headers["X-RateLimit-Remaining"] = str(remaining)
        response.headers["X-RateLimit-Reset"] = str(reset_seconds)

        return response
