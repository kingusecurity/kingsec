from __future__ import annotations

from typing import cast

from kingsec.application.ports.outbound import MetricsCollectorPort
from kingsec.domain.system_health import ResourceUsage


class ProcessMetricsCollector(MetricsCollectorPort):
    def __init__(self) -> None:
        self._prev_cpu = 0.0

    def collect_cpu(self) -> float:
        try:
            import psutil  # type: ignore[import-untyped]

            return cast(float, psutil.cpu_percent(interval=0.1))
        except ImportError:
            return 0.0

    def collect_memory(self) -> tuple[float, float]:
        try:
            import psutil

            mem = psutil.virtual_memory()
            return mem.percent, mem.used / (1024 * 1024)
        except ImportError:
            return 0.0, 0.0

    def collect_disk(self) -> tuple[float, float]:
        try:
            import psutil

            du = psutil.disk_usage("/")
            return du.percent, du.used / (1024 * 1024 * 1024)
        except ImportError:
            return 0.0, 0.0

    def collect_all(self) -> ResourceUsage:
        return ResourceUsage(
            cpu_percent=self.collect_cpu(),
            memory_percent=self.collect_memory()[0],
            memory_used_mb=self.collect_memory()[1],
            disk_percent=self.collect_disk()[0],
            disk_used_gb=self.collect_disk()[1],
        )
