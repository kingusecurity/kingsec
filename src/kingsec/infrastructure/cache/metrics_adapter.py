"""Adapter exposing MemoryCacheService's stats as CacheMetricsPort.

A separate, additive wrapper: MemoryCacheService itself is not modified,
since it's shared by the AI Copilot and Threat Intelligence subsystems
(see its own docstring) — this only reads its existing public attributes.
"""

from __future__ import annotations

from kingsec.application.ports.outbound.cache_metrics import CacheMetricsPort, CacheStats

from .memory_cache import MemoryCacheService


class MemoryCacheMetricsAdapter(CacheMetricsPort):
    """Reports statistics for a ``MemoryCacheService`` instance."""

    def __init__(self, cache: MemoryCacheService) -> None:
        self._cache = cache

    def stats(self) -> CacheStats:
        return CacheStats(
            size=self._cache.size,
            hit_ratio=self._cache.hit_ratio,
            hits=self._cache.hits,
            misses=self._cache.misses,
        )
