from __future__ import annotations

from abc import ABC, abstractmethod
from typing import Any

from kingsec.domain.dashboard import SeverityBreakdown, TrendPoint


class MetricsCalculatorPort(ABC):
    @abstractmethod
    def compute_severity_breakdown(self, findings: list[dict[str, Any]]) -> SeverityBreakdown: ...

    @abstractmethod
    def compute_trends(self, raw_data: list[dict[str, Any]], period: str, limit: int) -> list[TrendPoint]: ...

    @abstractmethod
    def compute_average(self, values: list[float]) -> float: ...
