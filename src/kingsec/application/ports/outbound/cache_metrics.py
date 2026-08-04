"""Port for cache introspection/statistics — application layer contract.

Distinct from ``CacheServicePort`` (get/set/exists — cache operations, defined
per-consumer in ai_copilot/threat_intelligence): this is read-only stats
reporting, used by health/performance endpoints. Infrastructure implements
this port; the application/adapter layers never import the concrete cache
class directly.
"""

from __future__ import annotations

from abc import ABC, abstractmethod
from dataclasses import dataclass


@dataclass(frozen=True)
class CacheStats:
    """A snapshot of cache utilization and effectiveness."""

    size: int
    hit_ratio: float
    hits: int
    misses: int


class CacheMetricsPort(ABC):
    """Abstract port for reading cache statistics."""

    @abstractmethod
    def stats(self) -> CacheStats:
        """Return a snapshot of current cache statistics."""
