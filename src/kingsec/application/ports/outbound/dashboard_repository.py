from __future__ import annotations

from abc import ABC, abstractmethod

from kingsec.domain.dashboard import (
    DashboardSummary,
    JobStatistics,
    NotificationStatistics,
    ScheduleStatistics,
    ScannerStatistics,
    SeverityBreakdown,
    TrendPoint,
    WorkerStatistics,
)


class DashboardRepositoryPort(ABC):
    @abstractmethod
    def get_summary(self) -> DashboardSummary:
        ...

    @abstractmethod
    def get_severity_breakdown(self) -> SeverityBreakdown:
        ...

    @abstractmethod
    def get_trend_data(self, period: str = "weekly", limit: int = 12) -> list[TrendPoint]:
        ...

    @abstractmethod
    def get_scanner_statistics(self) -> list[ScannerStatistics]:
        ...

    @abstractmethod
    def get_worker_statistics(self) -> list[WorkerStatistics]:
        ...

    @abstractmethod
    def get_job_statistics(self) -> JobStatistics:
        ...

    @abstractmethod
    def get_schedule_statistics(self) -> ScheduleStatistics:
        ...

    @abstractmethod
    def get_notification_statistics(self) -> NotificationStatistics:
        ...

    @abstractmethod
    def get_recent_activity(self, limit: int = 20) -> list[dict]:
        ...

    @abstractmethod
    def get_top_targets(self, limit: int = 10) -> list[tuple[str, int]]:
        ...

    @abstractmethod
    def get_active_users(self, limit: int = 10) -> list[tuple[str, int]]:
        ...
