from __future__ import annotations

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


class TestDashboardSummary:
    def test_defaults(self) -> None:
        s = DashboardSummary()
        assert s.total_scans == 0

    def test_with_values(self) -> None:
        s = DashboardSummary(total_scans=10, successful_scans=7, failed_scans=3)
        assert s.total_scans == 10
        assert s.successful_scans == 7
        assert s.failed_scans == 3


class TestSeverityBreakdown:
    def test_defaults(self) -> None:
        s = SeverityBreakdown()
        assert s.critical == 0

    def test_with_values(self) -> None:
        s = SeverityBreakdown(critical=5, high=10, medium=15, low=20, info=25)
        assert s.critical == 5
        assert s.high == 10
        assert s.info == 25


class TestTrendPoint:
    def test_create(self) -> None:
        p = TrendPoint(date="2025-01-01", value=42.0)
        assert p.date == "2025-01-01"
        assert p.value == 42.0


class TestScannerStatistics:
    def test_create(self) -> None:
        s = ScannerStatistics(scanner_id="s1", name="nmap")
        assert s.scanner_id == "s1"
        assert s.name == "nmap"
        assert s.total_scans == 0


class TestWorkerStatistics:
    def test_create(self) -> None:
        w = WorkerStatistics(worker_id="w1", status="running")
        assert w.worker_id == "w1"
        assert w.status == "running"


class TestScheduleStatistics:
    def test_create(self) -> None:
        s = ScheduleStatistics(total=10, active=5, paused=3, disabled=2)
        assert s.total == 10
        assert s.active == 5


class TestJobStatistics:
    def test_create(self) -> None:
        j = JobStatistics(pending=2, running=1, completed=10, failed=1, cancelled=0)
        assert j.pending == 2
        assert j.completed == 10


class TestNotificationStatistics:
    def test_create(self) -> None:
        n = NotificationStatistics(total=100, sent=80, failed=5, pending=10, read_count=5)
        assert n.total == 100
        assert n.sent == 80
