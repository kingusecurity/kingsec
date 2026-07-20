from __future__ import annotations

import threading
import time

from kingsec.application.ports.outbound.rate_limiter import RateLimiterPort
from kingsec.domain.rate_limit import RateLimitDecision, RateLimitPolicy


class SlidingWindowEntry:
    __slots__ = ("timestamps",)

    def __init__(self) -> None:
        self.timestamps: list[float] = []


class InMemoryRateLimiter(RateLimiterPort):
    def __init__(self) -> None:
        self._buckets: dict[str, SlidingWindowEntry] = {}
        self._lock = threading.Lock()

    def check(self, key: str, policy: RateLimitPolicy) -> RateLimitDecision:
        now = time.time()
        window_start = now - policy.window_seconds

        with self._lock:
            entry = self._buckets.get(key)
            if entry is None:
                return RateLimitDecision(
                    allowed=True,
                    limit=policy.max_requests,
                    remaining=policy.max_requests,
                    reset_seconds=0,
                )

            entry.timestamps = [t for t in entry.timestamps if t > window_start]
            count = len(entry.timestamps)
            allowed = count < policy.max_requests

            oldest = entry.timestamps[0] if entry.timestamps else now
            reset_seconds = max(
                0, int(policy.window_seconds - (now - oldest)) + 1
            ) if entry.timestamps else 0

            return RateLimitDecision(
                allowed=allowed,
                limit=policy.max_requests,
                remaining=max(0, policy.max_requests - count),
                reset_seconds=reset_seconds,
            )

    def record(self, key: str, policy: RateLimitPolicy) -> None:
        now = time.time()
        window_start = now - policy.window_seconds

        with self._lock:
            entry = self._buckets.get(key)
            if entry is None:
                entry = SlidingWindowEntry()
                self._buckets[key] = entry

            entry.timestamps = [t for t in entry.timestamps if t > window_start]
            entry.timestamps.append(now)

    def reset(self, key: str) -> None:
        with self._lock:
            self._buckets.pop(key, None)

    def _cleanup_expired(self, window_seconds: int) -> None:
        now = time.time()
        cutoff = now - window_seconds
        with self._lock:
            expired = [
                k for k, v in self._buckets.items()
                if not v.timestamps or max(v.timestamps) < cutoff
            ]
            for k in expired:
                del self._buckets[k]
