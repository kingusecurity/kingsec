"""Tests for MemoryCacheService."""

from __future__ import annotations

import pytest

from kingsec.infrastructure.cache.memory_cache import MemoryCacheService


class TestMemoryCacheService:
    def test_set_and_get(self) -> None:
        cache = MemoryCacheService(max_size=100, default_ttl=60)
        cache.set_sync("key1", "value1")
        assert cache.get_sync("key1") == "value1"

    def test_get_missing_key(self) -> None:
        cache = MemoryCacheService(max_size=100)
        assert cache.get_sync("missing") is None

    def test_delete(self) -> None:
        cache = MemoryCacheService(max_size=100)
        cache.set_sync("key1", "value1")
        cache.delete_sync("key1")
        assert cache.get_sync("key1") is None

    def test_delete_nonexistent(self) -> None:
        cache = MemoryCacheService(max_size=100)
        cache.delete_sync("missing")  # no-op

    def test_exists(self) -> None:
        cache = MemoryCacheService(max_size=100)
        cache.set_sync("key1", "value1")
        assert cache.exists_sync("key1") is True
        assert cache.exists_sync("missing") is False

    def test_ttl_expiration(self) -> None:
        cache = MemoryCacheService(max_size=100)
        # Manually set an entry with past expiration
        cache._store["key1"] = ("value1", 0.0)  # expires_at=0 means already expired
        assert cache.get_sync("key1") is None

    def test_ttl_nonzero_not_expired(self) -> None:
        cache = MemoryCacheService(max_size=100)
        cache.set_sync("key1", "value1", ttl=10)
        # Should still be valid
        assert cache.get_sync("key1") == "value1"

    def test_lru_eviction(self) -> None:
        cache = MemoryCacheService(max_size=3, default_ttl=300)
        cache.set_sync("a", 1)
        cache.set_sync("b", 2)
        cache.set_sync("c", 3)
        cache.set_sync("d", 4)  # evicts "a"
        assert cache.get_sync("a") is None
        assert cache.get_sync("b") == 2

    def test_overwrite(self) -> None:
        cache = MemoryCacheService(max_size=100)
        cache.set_sync("key1", "old")
        cache.set_sync("key1", "new")
        assert cache.get_sync("key1") == "new"

    def test_size(self) -> None:
        cache = MemoryCacheService(max_size=100)
        assert cache.size == 0
        cache.set_sync("a", 1)
        cache.set_sync("b", 2)
        assert cache.size == 2

    def test_hit_ratio(self) -> None:
        cache = MemoryCacheService(max_size=100)
        cache.set_sync("a", 1)
        cache.get_sync("a")  # hit
        cache.get_sync("b")  # miss
        assert cache.hits == 1
        assert cache.misses == 1
        assert cache.hit_ratio == 0.5

    def test_clear(self) -> None:
        cache = MemoryCacheService(max_size=100)
        cache.set_sync("a", 1)
        cache.set_sync("b", 2)
        cache.clear()
        assert cache.size == 0
        assert cache.hits == 0
        assert cache.misses == 0

    def test_evict_expired(self) -> None:
        cache = MemoryCacheService(max_size=100)
        # Manually set expired entry
        cache._store["a"] = (1, 0.0)  # already expired
        cache.set_sync("b", 2, ttl=300)
        removed = cache.evict_expired()
        assert removed == 1
        assert cache.size == 1

    @pytest.mark.asyncio
    async def test_async_get_set(self) -> None:
        cache = MemoryCacheService(max_size=100)
        await cache.set("key1", "value1", ttl=60)
        assert await cache.get("key1") == "value1"

    @pytest.mark.asyncio
    async def test_async_delete(self) -> None:
        cache = MemoryCacheService(max_size=100)
        await cache.set("key1", "value1", ttl=60)
        await cache.delete("key1")
        assert await cache.get("key1") is None

    @pytest.mark.asyncio
    async def test_async_exists(self) -> None:
        cache = MemoryCacheService(max_size=100)
        await cache.set("key1", "value1", ttl=60)
        assert await cache.exists("key1") is True
        assert await cache.exists("missing") is False
