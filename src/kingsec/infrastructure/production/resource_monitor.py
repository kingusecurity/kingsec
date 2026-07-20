from __future__ import annotations

from kingsec.application.ports.outbound import MetricsCollectorPort
from kingsec.domain.system_health import ResourceUsage


class ResourceMonitor(MetricsCollectorPort):
    def __init__(self, collector: MetricsCollectorPort) -> None:
        self._collector = collector

    def collect_cpu(self) -> float:
        return self._collector.collect_cpu()

    def collect_memory(self) -> tuple[float, float]:
        return self._collector.collect_memory()

    def collect_disk(self) -> tuple[float, float]:
        return self._collector.collect_disk()

    def collect_all(self) -> ResourceUsage:
        return self._collector.collect_all()
