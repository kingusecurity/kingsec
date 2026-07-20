from __future__ import annotations

from collections.abc import Sequence
from datetime import UTC, datetime, timedelta

from sqlalchemy import func, select, text
from sqlalchemy.orm import Session

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


class SQLAlchemyDashboardRepository(DashboardRepositoryPort):
    def __init__(self, session: Session) -> None:
        self._session = session

    def get_summary(self) -> DashboardSummary:
        from kingsec.infrastructure.persistence.models import AssessmentORM, FindingORM
        from kingsec.infrastructure.notifications.orm import NotificationORM

        total_scans = self._session.execute(
            select(func.count(AssessmentORM.id))
        ).scalar() or 0

        successful = self._session.execute(
            select(func.count(AssessmentORM.id)).where(AssessmentORM.status == "COMPLETED")
        ).scalar() or 0

        failed = self._session.execute(
            select(func.count(AssessmentORM.id)).where(AssessmentORM.status == "FAILED")
        ).scalar() or 0

        total_findings = self._session.execute(
            select(func.count(FindingORM.id))
        ).scalar() or 0

        critical = self._session.execute(
            select(func.count(FindingORM.id)).where(FindingORM.severity == "CRITICAL")
        ).scalar() or 0
        high = self._session.execute(
            select(func.count(FindingORM.id)).where(FindingORM.severity == "HIGH")
        ).scalar() or 0
        medium = self._session.execute(
            select(func.count(FindingORM.id)).where(FindingORM.severity == "MEDIUM")
        ).scalar() or 0
        low = self._session.execute(
            select(func.count(FindingORM.id)).where(FindingORM.severity == "LOW")
        ).scalar() or 0

        pending_notif = self._session.execute(
            select(func.count(NotificationORM.id)).where(NotificationORM.status == "pending")
        ).scalar() or 0
        failed_notif = self._session.execute(
            select(func.count(NotificationORM.id)).where(NotificationORM.status == "failed")
        ).scalar() or 0

        return DashboardSummary(
            total_scans=total_scans,
            successful_scans=successful,
            failed_scans=failed,
            total_findings=total_findings,
            critical_findings=critical,
            high_findings=high,
            medium_findings=medium,
            low_findings=low,
            pending_notifications=pending_notif,
            failed_notifications=failed_notif,
        )

    def get_severity_breakdown(self) -> SeverityBreakdown:
        from kingsec.infrastructure.persistence.models import FindingORM

        critical = self._session.execute(
            select(func.count(FindingORM.id)).where(FindingORM.severity == "CRITICAL")
        ).scalar() or 0
        high = self._session.execute(
            select(func.count(FindingORM.id)).where(FindingORM.severity == "HIGH")
        ).scalar() or 0
        medium = self._session.execute(
            select(func.count(FindingORM.id)).where(FindingORM.severity == "MEDIUM")
        ).scalar() or 0
        low = self._session.execute(
            select(func.count(FindingORM.id)).where(FindingORM.severity == "LOW")
        ).scalar() or 0
        info = self._session.execute(
            select(func.count(FindingORM.id)).where(FindingORM.severity == "INFO")
        ).scalar() or 0

        return SeverityBreakdown(
            critical=critical, high=high, medium=medium, low=low, info=info,
        )

    def get_trend_data(self, period: str = "weekly", limit: int = 12) -> list[TrendPoint]:
        from kingsec.infrastructure.persistence.models import AssessmentORM

        days_map = {"daily": 1, "weekly": 7, "monthly": 30}
        days = days_map.get(period, 7)
        since = (datetime.now(UTC) - timedelta(days=days * limit)).isoformat()

        stmt = (
            select(
                func.date(AssessmentORM.created_at).label("day"),
                func.count(AssessmentORM.id).label("count"),
            )
            .where(AssessmentORM.created_at >= since)
            .group_by(text("day"))
            .order_by(text("day"))
        )
        rows = self._session.execute(stmt).all()
        return [TrendPoint(date=str(row.day), value=float(row.count)) for row in rows]

    def get_scanner_statistics(self) -> list[ScannerStatistics]:
        return []

    def get_worker_statistics(self) -> list[WorkerStatistics]:
        return []

    def get_job_statistics(self) -> JobStatistics:
        from kingsec.infrastructure.persistence.models import AssessmentORM

        pending = self._session.execute(
            select(func.count(AssessmentORM.id)).where(AssessmentORM.status == "PENDING")
        ).scalar() or 0
        running = self._session.execute(
            select(func.count(AssessmentORM.id)).where(AssessmentORM.status == "RUNNING")
        ).scalar() or 0
        completed = self._session.execute(
            select(func.count(AssessmentORM.id)).where(AssessmentORM.status == "COMPLETED")
        ).scalar() or 0
        failed = self._session.execute(
            select(func.count(AssessmentORM.id)).where(AssessmentORM.status == "FAILED")
        ).scalar() or 0

        return JobStatistics(
            pending=pending, running=running, completed=completed, failed=failed,
        )

    def get_schedule_statistics(self) -> ScheduleStatistics:
        from kingsec.infrastructure.persistence.models import ScheduleORM

        total = self._session.execute(
            select(func.count(ScheduleORM.id))
        ).scalar() or 0
        active = self._session.execute(
            select(func.count(ScheduleORM.id)).where(ScheduleORM.status == "active")
        ).scalar() or 0
        paused = self._session.execute(
            select(func.count(ScheduleORM.id)).where(ScheduleORM.status == "paused")
        ).scalar() or 0
        disabled = self._session.execute(
            select(func.count(ScheduleORM.id)).where(ScheduleORM.status == "disabled")
        ).scalar() or 0

        return ScheduleStatistics(total=total, active=active, paused=paused, disabled=disabled)

    def get_notification_statistics(self) -> NotificationStatistics:
        from kingsec.infrastructure.notifications.orm import NotificationORM

        total = self._session.execute(
            select(func.count(NotificationORM.id))
        ).scalar() or 0
        sent = self._session.execute(
            select(func.count(NotificationORM.id)).where(NotificationORM.status == "sent")
        ).scalar() or 0
        failed = self._session.execute(
            select(func.count(NotificationORM.id)).where(NotificationORM.status == "failed")
        ).scalar() or 0
        pending = self._session.execute(
            select(func.count(NotificationORM.id)).where(NotificationORM.status == "pending")
        ).scalar() or 0
        read = self._session.execute(
            select(func.count(NotificationORM.id)).where(NotificationORM.status == "read")
        ).scalar() or 0

        return NotificationStatistics(total=total, sent=sent, failed=failed, pending=pending, read_count=read)

    def get_recent_activity(self, limit: int = 20) -> list[dict]:
        from kingsec.infrastructure.persistence.models import AssessmentORM

        stmt = (
            select(AssessmentORM)
            .order_by(AssessmentORM.created_at.desc())
            .limit(limit)
        )
        rows: Sequence[AssessmentORM] = self._session.execute(stmt).scalars().all()
        return [
            {
                "id": r.id,
                "type": "assessment",
                "action": r.status,
                "target": r.target_value,
                "timestamp": r.created_at,
            }
            for r in rows
        ]

    def get_top_targets(self, limit: int = 10) -> list[tuple[str, int]]:
        from kingsec.infrastructure.persistence.models import AssessmentORM

        stmt = (
            select(AssessmentORM.target_value, func.count(AssessmentORM.id).label("cnt"))
            .group_by(AssessmentORM.target_value)
            .order_by(text("cnt desc"))
            .limit(limit)
        )
        return [(str(row.target_value), int(row.cnt)) for row in self._session.execute(stmt).all()]

    def get_active_users(self, limit: int = 10) -> list[tuple[str, int]]:
        return []
