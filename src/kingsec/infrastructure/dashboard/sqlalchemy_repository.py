from __future__ import annotations

from collections.abc import Callable
from datetime import UTC, datetime, timedelta
from typing import Any

from sqlalchemy import func, select, text
from sqlalchemy.orm import Session

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


class SQLAlchemyDashboardRepository(DashboardRepositoryPort):
    def __init__(self, session_factory: Callable[[], Session]) -> None:
        self._session_factory = session_factory

    def get_summary(self) -> DashboardSummary:
        from kingsec.infrastructure.notifications.orm import NotificationORM
        from kingsec.infrastructure.persistence.models import AssessmentORM, FindingORM

        with self._session_factory() as session:
            # Single GROUP BY query for assessment status counts
            status_counts: dict[str, int] = {}
            rows = session.execute(
                select(AssessmentORM.status, func.count(AssessmentORM.id))
                .where(AssessmentORM.status.in_(["COMPLETED", "FAILED"]))
                .group_by(AssessmentORM.status)
            ).all()
            total_scans = session.execute(select(func.count(AssessmentORM.id))).scalar() or 0
            for status, cnt in rows:
                status_counts[status] = cnt

            # Single GROUP BY query for severity counts
            severity_rows = session.execute(
                select(FindingORM.severity, func.count(FindingORM.id))
                .where(FindingORM.severity.in_(["CRITICAL", "HIGH", "MEDIUM", "LOW"]))
                .group_by(FindingORM.severity)
            ).all()
            total_findings = session.execute(select(func.count(FindingORM.id))).scalar() or 0
            severity_map: dict[str, int] = {}
            for sev, cnt in severity_rows:
                severity_map[sev] = cnt

            # Single GROUP BY query for notification status counts
            notif_rows = session.execute(
                select(NotificationORM.status, func.count(NotificationORM.id))
                .where(NotificationORM.status.in_(["pending", "failed"]))
                .group_by(NotificationORM.status)
            ).all()
            notif_map: dict[str, int] = {}
            for status, cnt in notif_rows:
                notif_map[status] = cnt

            return DashboardSummary(
                total_scans=total_scans,
                successful_scans=status_counts.get("COMPLETED", 0),
                failed_scans=status_counts.get("FAILED", 0),
                total_findings=total_findings,
                critical_findings=severity_map.get("CRITICAL", 0),
                high_findings=severity_map.get("HIGH", 0),
                medium_findings=severity_map.get("MEDIUM", 0),
                low_findings=severity_map.get("LOW", 0),
                pending_notifications=notif_map.get("pending", 0),
                failed_notifications=notif_map.get("failed", 0),
            )

    def get_severity_breakdown(self) -> SeverityBreakdown:
        from kingsec.infrastructure.persistence.models import FindingORM

        with self._session_factory() as session:
            rows = session.execute(
                select(FindingORM.severity, func.count(FindingORM.id)).group_by(FindingORM.severity)
            ).all()
            counts: dict[str, int] = {}
            for sev, cnt in rows:
                counts[sev] = cnt

            return SeverityBreakdown(
                critical=counts.get("CRITICAL", 0),
                high=counts.get("HIGH", 0),
                medium=counts.get("MEDIUM", 0),
                low=counts.get("LOW", 0),
                info=counts.get("INFORMATIONAL", 0),
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
        with self._session_factory() as session:
            rows = session.execute(stmt).all()
            return [TrendPoint(date=str(row.day), value=float(row.count)) for row in rows]  # type: ignore[arg-type]

    def get_scanner_statistics(self) -> list[ScannerStatistics]:
        return []

    def get_worker_statistics(self) -> list[WorkerStatistics]:
        return []

    def get_job_statistics(self) -> JobStatistics:
        from kingsec.infrastructure.persistence.models import AssessmentORM

        with self._session_factory() as session:
            rows = session.execute(
                select(AssessmentORM.status, func.count(AssessmentORM.id))
                .where(AssessmentORM.status.in_(["PENDING", "RUNNING", "COMPLETED", "FAILED"]))
                .group_by(AssessmentORM.status)
            ).all()
            counts: dict[str, int] = {}
            for status, cnt in rows:
                counts[status] = cnt

            return JobStatistics(
                pending=counts.get("PENDING", 0),
                running=counts.get("RUNNING", 0),
                completed=counts.get("COMPLETED", 0),
                failed=counts.get("FAILED", 0),
            )

    def get_schedule_statistics(self) -> ScheduleStatistics:
        from kingsec.infrastructure.persistence.models import ScheduleORM

        with self._session_factory() as session:
            total = session.execute(select(func.count(ScheduleORM.id))).scalar() or 0
            rows = session.execute(
                select(ScheduleORM.status, func.count(ScheduleORM.id))
                .where(ScheduleORM.status.in_(["active", "paused", "disabled"]))
                .group_by(ScheduleORM.status)
            ).all()
            counts: dict[str, int] = {}
            for status, cnt in rows:
                counts[status] = cnt

            return ScheduleStatistics(
                total=total,
                active=counts.get("active", 0),
                paused=counts.get("paused", 0),
                disabled=counts.get("disabled", 0),
            )

    def get_notification_statistics(self) -> NotificationStatistics:
        from kingsec.infrastructure.notifications.orm import NotificationORM

        with self._session_factory() as session:
            total = session.execute(select(func.count(NotificationORM.id))).scalar() or 0
            rows = session.execute(
                select(NotificationORM.status, func.count(NotificationORM.id))
                .where(NotificationORM.status.in_(["sent", "failed", "pending", "read"]))
                .group_by(NotificationORM.status)
            ).all()
            counts: dict[str, int] = {}
            for status, cnt in rows:
                counts[status] = cnt

            return NotificationStatistics(
                total=total,
                sent=counts.get("sent", 0),
                failed=counts.get("failed", 0),
                pending=counts.get("pending", 0),
                read_count=counts.get("read", 0),
            )

    def get_recent_activity(self, limit: int = 20) -> list[dict[str, Any]]:
        from kingsec.infrastructure.persistence.models import AssessmentORM

        stmt = (
            select(
                AssessmentORM.id,
                AssessmentORM.status,
                AssessmentORM.target_value,
                AssessmentORM.created_at,
            )
            .order_by(AssessmentORM.created_at.desc())
            .limit(limit)
        )
        with self._session_factory() as session:
            rows = session.execute(stmt).all()
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
        with self._session_factory() as session:
            return [(str(row.target_value), int(row.cnt)) for row in session.execute(stmt).all()]

    def get_active_users(self, limit: int = 10) -> list[tuple[str, int]]:
        return []
