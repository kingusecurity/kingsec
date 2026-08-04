"""MemoryCacheMetricsAdapter: CacheMetricsPort backed by MemoryCacheService.

This adapter exists so adapters/inbound/web/health_routes.py can read cache
statistics via a port instead of importing MemoryCacheService directly
(an import-linter layering violation) — MemoryCacheService itself is
untouched, since it's shared by other subsystems.
"""

from __future__ import annotations

from kingsec.application.ports import CacheMetricsPort, CacheStats
from kingsec.infrastructure.cache.memory_cache import MemoryCacheService
from kingsec.infrastructure.cache.metrics_adapter import MemoryCacheMetricsAdapter


class TestMemoryCacheMetricsAdapter:
    def test_is_a_cache_metrics_port(self) -> None:
        cache = MemoryCacheService(max_size=10)
        adapter = MemoryCacheMetricsAdapter(cache)
        assert isinstance(adapter, CacheMetricsPort)

    def test_reports_stats_from_the_underlying_cache(self) -> None:
        cache = MemoryCacheService(max_size=10)
        cache.set_sync("a", 1)
        cache.get_sync("a")  # hit
        cache.get_sync("missing")  # miss

        stats = MemoryCacheMetricsAdapter(cache).stats()

        assert stats == CacheStats(
            size=cache.size,
            hit_ratio=cache.hit_ratio,
            hits=cache.hits,
            misses=cache.misses,
        )
        assert stats.hits == 1
        assert stats.misses == 1
