from __future__ import annotations

from typing import Any

from kingsec.application.ports.outbound import DashboardRepositoryPort
from kingsec.domain.dashboard import (
    DashboardSummary,
    JobStatistics,
    NotificationStatistics,
    ScannerStatistics,
    ScheduleStatistics,
    SeverityBreakdown,
    TrendPoint,
    WorkerStatistics,
)


class GetDashboardSummary:
    def __init__(self, repo: DashboardRepositoryPort) -> None:
        self._repo = repo

    def execute(self) -> DashboardSummary:
        return self._repo.get_summary()


class GetSeverityBreakdown:
    def __init__(self, repo: DashboardRepositoryPort) -> None:
        self._repo = repo

    def execute(self) -> SeverityBreakdown:
        return self._repo.get_severity_breakdown()


class GetTrendData:
    def __init__(self, repo: DashboardRepositoryPort) -> None:
        self._repo = repo

    def execute(self, period: str = "weekly", limit: int = 12) -> list[TrendPoint]:
        return self._repo.get_trend_data(period=period, limit=limit)


class GetScannerStatistics:
    def __init__(self, repo: DashboardRepositoryPort) -> None:
        self._repo = repo

    def execute(self) -> list[ScannerStatistics]:
        return self._repo.get_scanner_statistics()


class GetWorkerStatistics:
    def __init__(self, repo: DashboardRepositoryPort) -> None:
        self._repo = repo

    def execute(self) -> list[WorkerStatistics]:
        return self._repo.get_worker_statistics()


class GetJobStatistics:
    def __init__(self, repo: DashboardRepositoryPort) -> None:
        self._repo = repo

    def execute(self) -> JobStatistics:
        return self._repo.get_job_statistics()


class GetScheduleStatistics:
    def __init__(self, repo: DashboardRepositoryPort) -> None:
        self._repo = repo

    def execute(self) -> ScheduleStatistics:
        return self._repo.get_schedule_statistics()


class GetNotificationStatistics:
    def __init__(self, repo: DashboardRepositoryPort) -> None:
        self._repo = repo

    def execute(self) -> NotificationStatistics:
        return self._repo.get_notification_statistics()


class GetRecentActivity:
    def __init__(self, repo: DashboardRepositoryPort) -> None:
        self._repo = repo

    def execute(self, limit: int = 20) -> list[dict[str, Any]]:
        return self._repo.get_recent_activity(limit=limit)


class GetTopTargets:
    def __init__(self, repo: DashboardRepositoryPort) -> None:
        self._repo = repo

    def execute(self, limit: int = 10) -> list[tuple[str, int]]:
        return self._repo.get_top_targets(limit=limit)


class GetActiveUsers:
    def __init__(self, repo: DashboardRepositoryPort) -> None:
        self._repo = repo

    def execute(self, limit: int = 10) -> list[tuple[str, int]]:
        return self._repo.get_active_users(limit=limit)
