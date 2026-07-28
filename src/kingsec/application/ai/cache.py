from __future__ import annotations

import time
from collections.abc import Callable


class PromptCache:
    """TTL cache for identical AI prompts to avoid redundant API calls."""

    def __init__(self, default_ttl_seconds: int = 300, max_size: int = 500) -> None:
        self._ttl = default_ttl_seconds
        self._max_size = max_size
        self._cache: dict[str, tuple[float, str]] = {}

    def get_or_compute(self, key: str, compute: Callable[[], str]) -> str:
        """Return cached result if fresh, otherwise compute and cache."""
        now = time.time()
        cached = self._cache.get(key)
        if cached is not None:
            expires_at, value = cached
            if now < expires_at:
                return value
            del self._cache[key]
        result = compute()
        self._cache[key] = (now + self._ttl, result)
        if len(self._cache) > self._max_size:
            self._evict()
        return result

    def invalidate(self, key: str) -> None:
        self._cache.pop(key, None)

    def clear(self) -> None:
        self._cache.clear()

    def _evict(self) -> None:
        oldest = min(self._cache.items(), key=lambda kv: kv[1][0])
        del self._cache[oldest[0]]
