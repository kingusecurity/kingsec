"""In-memory TTL cache implementing the CacheServicePort protocols."""

from __future__ import annotations

import threading
import time
from collections import OrderedDict
from typing import Any


class MemoryCacheService:
    """Thread-safe in-memory LRU cache with per-key TTL.

    Implements the ``CacheServicePort`` protocol used by both the Threat
    Intelligence and AI Copilot subsystems.  Entries are evicted on access
    when expired, and the LRU policy drops the least-recently-used entry
    when ``max_size`` is reached.
    """

    def __init__(self, max_size: int = 10_000, default_ttl: int = 300) -> None:
        self._max_size = max_size
        self._default_ttl = default_ttl
        self._store: OrderedDict[str, tuple[Any, float]] = OrderedDict()
        self._lock = threading.Lock()
        self._hits = 0
        self._misses = 0

    # ------------------------------------------------------------------
    # CacheServicePort protocol (async)
    # ------------------------------------------------------------------

    async def get(self, key: str) -> Any | None:
        return self.get_sync(key)

    async def set(self, key: str, value: Any, ttl: int = 300) -> None:
        self.set_sync(key, value, ttl)

    async def delete(self, key: str) -> None:
        self.delete_sync(key)

    async def exists(self, key: str) -> bool:
        return self.exists_sync(key)

    # ------------------------------------------------------------------
    # Sync API (used by non-async callers and benchmarks)
    # ------------------------------------------------------------------

    def get_sync(self, key: str) -> Any | None:
        with self._lock:
            entry = self._store.get(key)
            if entry is None:
                self._misses += 1
                return None
            value, expires_at = entry
            if time.monotonic() > expires_at:
                del self._store[key]
                self._misses += 1
                return None
            self._store.move_to_end(key)
            self._hits += 1
            return value

    def set_sync(self, key: str, value: Any, ttl: int = 0) -> None:
        if ttl <= 0:
            ttl = self._default_ttl
        expires_at = time.monotonic() + ttl
        with self._lock:
            if key in self._store:
                del self._store[key]
            elif len(self._store) >= self._max_size:
                self._store.popitem(last=False)
            self._store[key] = (value, expires_at)

    def delete_sync(self, key: str) -> None:
        with self._lock:
            self._store.pop(key, None)

    def exists_sync(self, key: str) -> bool:
        with self._lock:
            entry = self._store.get(key)
            if entry is None:
                return False
            _value, expires_at = entry
            if time.monotonic() > expires_at:
                del self._store[key]
                return False
            return True

    # ------------------------------------------------------------------
    # Metrics
    # ------------------------------------------------------------------

    @property
    def size(self) -> int:
        with self._lock:
            return len(self._store)

    @property
    def hit_ratio(self) -> float:
        total = self._hits + self._misses
        return self._hits / total if total > 0 else 0.0

    @property
    def hits(self) -> int:
        return self._hits

    @property
    def misses(self) -> int:
        return self._misses

    def clear(self) -> None:
        with self._lock:
            self._store.clear()
            self._hits = 0
            self._misses = 0

    def evict_expired(self) -> int:
        """Remove all expired entries. Returns count removed."""
        now = time.monotonic()
        removed = 0
        with self._lock:
            expired = [k for k, (_, exp) in self._store.items() if now > exp]
            for k in expired:
                del self._store[k]
                removed += 1
        return removed
