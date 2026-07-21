from __future__ import annotations

import threading
import time

from kingsec.domain.rate_limit import RateLimitGroup, RateLimitPolicy
from kingsec.infrastructure.rate_limit.in_memory_rate_limiter import (
    InMemoryRateLimiter,
)


class TestInMemoryRateLimiter:
    def test_allows_first_request(self) -> None:
        limiter = InMemoryRateLimiter()
        policy = RateLimitPolicy(
            group=RateLimitGroup.LOGIN,
            max_requests=5,
            window_seconds=900,
        )
        decision = limiter.check("ip:1.2.3.4", policy)
        assert decision.allowed
        assert decision.remaining == 5

    def test_tracks_requests(self) -> None:
        limiter = InMemoryRateLimiter()
        policy = RateLimitPolicy(
            group=RateLimitGroup.LOGIN,
            max_requests=3,
            window_seconds=900,
        )
        for _ in range(3):
            limiter.record("ip:1.2.3.4", policy)
        decision = limiter.check("ip:1.2.3.4", policy)
        assert decision.remaining == 0
        assert decision.allowed is False

    def test_resets_key(self) -> None:
        limiter = InMemoryRateLimiter()
        policy = RateLimitPolicy(
            group=RateLimitGroup.LOGIN,
            max_requests=3,
            window_seconds=900,
        )
        for _ in range(3):
            limiter.record("ip:1.2.3.4", policy)
        limiter.reset("ip:1.2.3.4")
        decision = limiter.check("ip:1.2.3.4", policy)
        assert decision.remaining == 3

    def test_sliding_window_expires(self) -> None:
        limiter = InMemoryRateLimiter()
        policy = RateLimitPolicy(
            group=RateLimitGroup.LOGIN,
            max_requests=2,
            window_seconds=1,
        )
        limiter.record("ip:1.2.3.4", policy)
        limiter.record("ip:1.2.3.4", policy)
        decision = limiter.check("ip:1.2.3.4", policy)
        assert not decision.allowed

        time.sleep(1.1)
        decision = limiter.check("ip:1.2.3.4", policy)
        assert decision.allowed
        assert decision.remaining >= 1

    def test_different_keys_independent(self) -> None:
        limiter = InMemoryRateLimiter()
        policy = RateLimitPolicy(
            group=RateLimitGroup.LOGIN,
            max_requests=1,
            window_seconds=900,
        )
        limiter.record("ip:1.1.1.1", policy)
        limiter.record("ip:2.2.2.2", policy)

        assert not limiter.check("ip:1.1.1.1", policy).allowed
        assert not limiter.check("ip:2.2.2.2", policy).allowed

        assert limiter.check("ip:3.3.3.3", policy).allowed

    def test_cleanup_expired_entries(self) -> None:
        limiter = InMemoryRateLimiter()
        policy = RateLimitPolicy(
            group=RateLimitGroup.LOGIN,
            max_requests=5,
            window_seconds=1,
        )
        limiter.record("ip:old", policy)
        time.sleep(1.1)
        limiter.record("ip:new", policy)

        limiter._cleanup_expired(1)
        decision_old = limiter.check("ip:old", policy)
        decision_new = limiter.check("ip:new", policy)

        assert decision_old.remaining == 5
        assert decision_new.remaining == 4

    def test_thread_safety(self) -> None:
        limiter = InMemoryRateLimiter()
        policy = RateLimitPolicy(
            group=RateLimitGroup.LOGIN,
            max_requests=1000,
            window_seconds=900,
        )
        errors = []

        def hammer() -> None:
            for _ in range(100):
                try:
                    limiter.record("ip:shared", policy)
                except Exception as e:
                    errors.append(e)

        threads = [threading.Thread(target=hammer) for _ in range(10)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()

        assert not errors
        decision = limiter.check("ip:shared", policy)
        assert decision.remaining >= 0
