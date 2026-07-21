from __future__ import annotations

from abc import ABC, abstractmethod

from kingsec.domain.system_health import ResourceUsage


class MetricsCollectorPort(ABC):
    @abstractmethod
    def collect_cpu(self) -> float: ...

    @abstractmethod
    def collect_memory(self) -> tuple[float, float]: ...

    @abstractmethod
    def collect_disk(self) -> tuple[float, float]: ...

    @abstractmethod
    def collect_all(self) -> ResourceUsage: ...
