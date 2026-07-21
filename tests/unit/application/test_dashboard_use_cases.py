from __future__ import annotations

from kingsec.application.analytics_service import AnalyticsService
from kingsec.infrastructure.dashboard.in_memory import InMemoryDashboardRepository


class TestGetDashboardSummary:
    def setup_method(self) -> None:
        self.repo = InMemoryDashboardRepository()
        self.service = AnalyticsService(self.repo)

    def test_empty_summary(self) -> None:
        s = self.service.get_summary()
        assert s.total_scans == 0

    def test_summary_with_data(self) -> None:
        self.repo.seed_assessment("COMPLETED")
        self.repo.seed_assessment("FAILED")
        self.repo.seed_assessment("COMPLETED")
        s = self.service.get_summary()
        assert s.total_scans == 3
        assert s.successful_scans == 2
        assert s.failed_scans == 1


class TestGetSeverityBreakdown:
    def setup_method(self) -> None:
        self.repo = InMemoryDashboardRepository()
        self.service = AnalyticsService(self.repo)

    def test_empty(self) -> None:
        s = self.service.get_severity_breakdown()
        assert s.critical == 0

    def test_with_findings(self) -> None:
        self.repo.seed_finding("CRITICAL")
        self.repo.seed_finding("HIGH")
        self.repo.seed_finding("HIGH")
        self.repo.seed_finding("LOW")
        s = self.service.get_severity_breakdown()
        assert s.critical == 1
        assert s.high == 2
        assert s.low == 1
        assert s.medium == 0


class TestGetTrendData:
    def setup_method(self) -> None:
        self.repo = InMemoryDashboardRepository()
        self.service = AnalyticsService(self.repo)
        from datetime import UTC, datetime, timedelta

        base = datetime.now(UTC)
        for i in range(5):
            self.repo.seed_assessment("COMPLETED", created_at=(base - timedelta(days=i * 7)).isoformat())

    def test_trend_returns_points(self) -> None:
        points = self.service.get_trend_data(period="weekly", limit=12)
        assert len(points) == 12
        assert any(p.value > 0 for p in points)


class TestGetJobStatistics:
    def setup_method(self) -> None:
        self.repo = InMemoryDashboardRepository()
        self.service = AnalyticsService(self.repo)

    def test_job_stats(self) -> None:
        self.repo.seed_assessment("PENDING")
        self.repo.seed_assessment("RUNNING")
        self.repo.seed_assessment("COMPLETED")
        self.repo.seed_assessment("FAILED")
        j = self.service.get_job_statistics()
        assert j.pending == 1
        assert j.running == 1
        assert j.completed == 1
        assert j.failed == 1


class TestGetScheduleStatistics:
    def setup_method(self) -> None:
        self.repo = InMemoryDashboardRepository()
        self.service = AnalyticsService(self.repo)

    def test_schedule_stats(self) -> None:
        self.repo.seed_schedule("active")
        self.repo.seed_schedule("active")
        self.repo.seed_schedule("paused")
        s = self.service.get_schedule_statistics()
        assert s.total == 3
        assert s.active == 2
        assert s.paused == 1


class TestGetNotificationStatistics:
    def setup_method(self) -> None:
        self.repo = InMemoryDashboardRepository()
        self.service = AnalyticsService(self.repo)

    def test_notification_stats(self) -> None:
        self.repo.seed_notification("sent")
        self.repo.seed_notification("sent")
        self.repo.seed_notification("failed")
        self.repo.seed_notification("pending")
        n = self.service.get_notification_statistics()
        assert n.total == 4
        assert n.sent == 2
        assert n.failed == 1
        assert n.pending == 1


class TestGetRecentActivity:
    def setup_method(self) -> None:
        self.repo = InMemoryDashboardRepository()
        self.service = AnalyticsService(self.repo)

    def test_recent_activity(self) -> None:
        self.repo.seed_assessment("COMPLETED", target="example.com")
        activity = self.service.get_recent_activity(limit=10)
        assert len(activity) == 1
        assert activity[0]["target"] == "example.com"


class TestGetTopTargets:
    def setup_method(self) -> None:
        self.repo = InMemoryDashboardRepository()
        self.service = AnalyticsService(self.repo)

    def test_top_targets(self) -> None:
        self.repo.seed_assessment("COMPLETED", target="a.com")
        self.repo.seed_assessment("COMPLETED", target="a.com")
        self.repo.seed_assessment("COMPLETED", target="b.com")
        targets = self.service.get_top_targets(limit=5)
        assert len(targets) == 2
        assert targets[0] == ("a.com", 2)
        assert targets[1] == ("b.com", 1)
