"""Port for reading performance/operation metrics — application layer contract.

Return types are intentionally loose (``Any``): callers (currently only the
metrics adapter routes) only ever read plain numeric attributes off the
result, and the concrete snapshot/stats shapes are defined in infrastructure
(``kingsec.infrastructure.monitoring.performance_metrics``) — the application
layer must not import that module to name them.
"""

from __future__ import annotations

from abc import ABC, abstractmethod
from typing import Any


class PerformanceMetricsPort(ABC):
    """Abstract port for reading performance and per-operation metrics."""

    @abstractmethod
    def snapshot(self) -> Any:
        """Return a snapshot of current performance metrics."""

    @abstractmethod
    def get_operation_stats(self, operation_name: str) -> Any:
        """Return latency stats for a named operation."""
