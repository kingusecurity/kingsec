from __future__ import annotations

from datetime import UTC, datetime, timedelta

from kingsec.application.ports.outbound import DashboardRepositoryPort
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


class InMemoryDashboardRepository(DashboardRepositoryPort):
    def __init__(self) -> None:
        self._assessments: list[dict] = []
        self._findings: list[dict] = []
        self._notifications: list[dict] = []
        self._schedules: list[dict] = []

    def seed_assessment(self, status: str, target: str = "example.com", created_at: str | None = None) -> None:
        self._assessments.append({
            "id": f"a-{len(self._assessments)}",
            "target_value": target,
            "status": status,
            "created_at": created_at or datetime.now(UTC).isoformat(),
        })

    def seed_finding(self, severity: str) -> None:
        self._findings.append({
            "id": f"f-{len(self._findings)}",
            "severity": severity,
            "assessment_id": "a-0",
        })

    def seed_notification(self, status: str) -> None:
        self._notifications.append({
            "id": f"n-{len(self._notifications)}",
            "status": status,
        })

    def seed_schedule(self, status: str) -> None:
        self._schedules.append({
            "id": f"s-{len(self._schedules)}",
            "status": status,
        })

    def get_summary(self) -> DashboardSummary:
        return DashboardSummary(
            total_scans=len(self._assessments),
            successful_scans=sum(1 for a in self._assessments if a["status"] == "COMPLETED"),
            failed_scans=sum(1 for a in self._assessments if a["status"] == "FAILED"),
            total_findings=len(self._findings),
            critical_findings=sum(1 for f in self._findings if f["severity"] == "CRITICAL"),
            high_findings=sum(1 for f in self._findings if f["severity"] == "HIGH"),
            medium_findings=sum(1 for f in self._findings if f["severity"] == "MEDIUM"),
            low_findings=sum(1 for f in self._findings if f["severity"] == "LOW"),
            pending_notifications=sum(1 for n in self._notifications if n["status"] == "pending"),
            failed_notifications=sum(1 for n in self._notifications if n["status"] == "failed"),
        )

    def get_severity_breakdown(self) -> SeverityBreakdown:
        return SeverityBreakdown(
            critical=sum(1 for f in self._findings if f["severity"] == "CRITICAL"),
            high=sum(1 for f in self._findings if f["severity"] == "HIGH"),
            medium=sum(1 for f in self._findings if f["severity"] == "MEDIUM"),
            low=sum(1 for f in self._findings if f["severity"] == "LOW"),
            info=sum(1 for f in self._findings if f["severity"] == "INFO"),
        )

    def get_trend_data(self, period: str = "weekly", limit: int = 12) -> list[TrendPoint]:
        today = datetime.now(UTC).date()
        result: list[TrendPoint] = []
        days_map = {"daily": 1, "weekly": 7, "monthly": 30}
        step = days_map.get(period, 7)
        for i in range(limit):
            end = today - timedelta(days=i * step)
            start = end - timedelta(days=step - 1)
            count = sum(
                1 for a in self._assessments
                if a.get("created_at", "")[:10] >= start.isoformat()[:10]
                and a.get("created_at", "")[:10] <= end.isoformat()[:10]
            )
            result.append(TrendPoint(date=end.isoformat(), value=float(count)))
        result.reverse()
        return result

    def get_scanner_statistics(self) -> list[ScannerStatistics]:
        return []

    def get_worker_statistics(self) -> list[WorkerStatistics]:
        return []

    def get_job_statistics(self) -> JobStatistics:
        return JobStatistics(
            pending=sum(1 for a in self._assessments if a["status"] == "PENDING"),
            running=sum(1 for a in self._assessments if a["status"] == "RUNNING"),
            completed=sum(1 for a in self._assessments if a["status"] == "COMPLETED"),
            failed=sum(1 for a in self._assessments if a["status"] == "FAILED"),
        )

    def get_schedule_statistics(self) -> ScheduleStatistics:
        return ScheduleStatistics(
            total=len(self._schedules),
            active=sum(1 for s in self._schedules if s["status"] == "active"),
            paused=sum(1 for s in self._schedules if s["status"] == "paused"),
            disabled=sum(1 for s in self._schedules if s["status"] == "disabled"),
        )

    def get_notification_statistics(self) -> NotificationStatistics:
        return NotificationStatistics(
            total=len(self._notifications),
            sent=sum(1 for n in self._notifications if n["status"] == "sent"),
            failed=sum(1 for n in self._notifications if n["status"] == "failed"),
            pending=sum(1 for n in self._notifications if n["status"] == "pending"),
            read_count=sum(1 for n in self._notifications if n["status"] == "read"),
        )

    def get_recent_activity(self, limit: int = 20) -> list[dict]:
        sorted_a = sorted(self._assessments, key=lambda a: a.get("created_at", ""), reverse=True)
        return [
            {"id": a["id"], "type": "assessment", "action": a["status"], "target": a["target_value"], "timestamp": a.get("created_at", "")}
            for a in sorted_a[:limit]
        ]

    def get_top_targets(self, limit: int = 10) -> list[tuple[str, int]]:
        counts: dict[str, int] = {}
        for a in self._assessments:
            t = a["target_value"]
            counts[t] = counts.get(t, 0) + 1
        sorted_counts = sorted(counts.items(), key=lambda x: x[1], reverse=True)
        return sorted_counts[:limit]

    def get_active_users(self, limit: int = 10) -> list[tuple[str, int]]:
        return []
