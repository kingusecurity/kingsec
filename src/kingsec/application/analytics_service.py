from __future__ import annotations

from kingsec.application.ports.analytics_service import AnalyticsServicePort
from kingsec.application.ports.outbound import DashboardRepositoryPort
from kingsec.application.use_cases.dashboard import (
    GetActiveUsers,
    GetDashboardSummary,
    GetJobStatistics,
    GetNotificationStatistics,
    GetRecentActivity,
    GetScheduleStatistics,
    GetScannerStatistics,
    GetSeverityBreakdown,
    GetTopTargets,
    GetTrendData,
    GetWorkerStatistics,
)
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


class AnalyticsService(AnalyticsServicePort):
    def __init__(self, repo: DashboardRepositoryPort) -> None:
        self._summary = GetDashboardSummary(repo)
        self._severity = GetSeverityBreakdown(repo)
        self._trends = GetTrendData(repo)
        self._scanners = GetScannerStatistics(repo)
        self._workers = GetWorkerStatistics(repo)
        self._jobs = GetJobStatistics(repo)
        self._schedules = GetScheduleStatistics(repo)
        self._notifications = GetNotificationStatistics(repo)
        self._activity = GetRecentActivity(repo)
        self._targets = GetTopTargets(repo)
        self._users = GetActiveUsers(repo)

    def get_summary(self) -> DashboardSummary:
        return self._summary.execute()

    def get_severity_breakdown(self) -> SeverityBreakdown:
        return self._severity.execute()

    def get_trend_data(self, period: str = "weekly", limit: int = 12) -> list[TrendPoint]:
        return self._trends.execute(period=period, limit=limit)

    def get_scanner_statistics(self) -> list[ScannerStatistics]:
        return self._scanners.execute()

    def get_worker_statistics(self) -> list[WorkerStatistics]:
        return self._workers.execute()

    def get_job_statistics(self) -> JobStatistics:
        return self._jobs.execute()

    def get_schedule_statistics(self) -> ScheduleStatistics:
        return self._schedules.execute()

    def get_notification_statistics(self) -> NotificationStatistics:
        return self._notifications.execute()

    def get_recent_activity(self, limit: int = 20) -> list[dict]:
        return self._activity.execute(limit=limit)

    def get_top_targets(self, limit: int = 10) -> list[tuple[str, int]]:
        return self._targets.execute(limit=limit)

    def get_active_users(self, limit: int = 10) -> list[tuple[str, int]]:
        return self._users.execute(limit=limit)
