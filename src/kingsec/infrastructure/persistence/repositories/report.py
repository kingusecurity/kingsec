from __future__ import annotations

import builtins

from sqlalchemy import func, select
from sqlalchemy.orm import Session

from kingsec.application import ReportNotFoundError, ReportRepository
from kingsec.application.ports.repositories import ReportProjection
from kingsec.domain import AssessmentId, Report
from kingsec.infrastructure.persistence.mappers import report_to_domain, report_to_orm
from kingsec.infrastructure.persistence.models import ReportORM

_SEVERITY_ORDER: dict[str, int] = {
    "CRITICAL": 4,
    "HIGH": 3,
    "MEDIUM": 2,
    "LOW": 1,
    "INFORMATIONAL": 0,
}

_ALLOWED_ORDER_COLS = frozenset({
    "generated_at",
    "target",
    "verdict_highest_severity",
    "total_findings",
})


class SQLAlchemyReportRepository(ReportRepository):
    """Implements :class:`ReportRepository` on a caller-owned session."""

    def __init__(self, session: Session) -> None:
        self._session = session

    def save(self, report: Report) -> None:
        self._session.merge(report_to_orm(report))

    def get(self, assessment_id: AssessmentId) -> Report:
        orm = self._session.get(ReportORM, assessment_id.value)
        if orm is None:
            raise ReportNotFoundError(assessment_id.value)
        return report_to_domain(orm)

    def list(
        self,
        *,
        limit: int = 50,
        offset: int = 0,
        order_by: str = "generated_at",
        order_dir: str = "desc",
        search: str | None = None,
        severity: str | None = None,
        target: str | None = None,
    ) -> tuple[builtins.list[ReportProjection], int]:
        stmt = select(ReportORM)
        count_stmt = select(func.count()).select_from(ReportORM)

        if search:
            pattern = f"%{search}%"
            stmt = stmt.where(ReportORM.target.ilike(pattern))
            count_stmt = count_stmt.where(ReportORM.target.ilike(pattern))
        if severity:
            stmt = stmt.where(ReportORM.verdict_highest_severity == severity.upper())
            count_stmt = count_stmt.where(ReportORM.verdict_highest_severity == severity.upper())
        if target:
            stmt = stmt.where(ReportORM.target == target)
            count_stmt = count_stmt.where(ReportORM.target == target)

        col = order_by if order_by in _ALLOWED_ORDER_COLS else "generated_at"
        order_col = getattr(ReportORM, col, ReportORM.generated_at)

        if col == "verdict_highest_severity":
            stmt = stmt.order_by(
                func.coalesce(
                    func.nullif(ReportORM.verdict_highest_severity, ""), ""
                ).desc() if order_dir == "desc" else func.coalesce(
                    func.nullif(ReportORM.verdict_highest_severity, ""), ""
                ).asc()
            )
        elif order_dir == "desc":
            stmt = stmt.order_by(order_col.desc())
        else:
            stmt = stmt.order_by(order_col.asc())

        total = self._session.execute(count_stmt).scalar() or 0
        stmt = stmt.offset(offset).limit(limit)
        orms = self._session.execute(stmt).scalars().all()

        projections = []
        for orm in orms:
            sc = self._parse_severity_counts(orm.severity_counts)
            projections.append(
                ReportProjection(
                    assessment_id=orm.assessment_id,
                    target=orm.target,
                    generated_at=orm.generated_at,
                    verdict_headline=orm.verdict_headline,
                    verdict_highest_severity=orm.verdict_highest_severity,
                    verdict_action_required=orm.verdict_action_required,
                    total_findings=len(orm.entries),
                    critical_count=sc.get("CRITICAL", 0),
                    high_count=sc.get("HIGH", 0),
                    medium_count=sc.get("MEDIUM", 0),
                    low_count=sc.get("LOW", 0),
                    info_count=sc.get("INFORMATIONAL", 0),
                    executive_score=self._compute_score(sc),
                    format="pdf",
                    file_size=0,
                )
            )
        return projections, total

    def count(self) -> int:
        return self._session.execute(select(func.count()).select_from(ReportORM)).scalar() or 0

    @staticmethod
    def _parse_severity_counts(severity_counts: list) -> dict[str, int]:
        result: dict[str, int] = {}
        if not severity_counts:
            return result
        for entry in severity_counts:
            if isinstance(entry, (list, tuple)) and len(entry) >= 2:
                result[str(entry[0]).upper()] = int(entry[1])
            elif isinstance(entry, dict):
                sev = str(entry.get("severity", entry.get("name", ""))).upper()
                cnt = int(entry.get("count", 0))
                if sev:
                    result[sev] = cnt
        return result

    @staticmethod
    def _compute_score(severity_counts: dict[str, int]) -> float:
        penalty = (
            severity_counts.get("CRITICAL", 0) * 25
            + severity_counts.get("HIGH", 0) * 10
            + severity_counts.get("MEDIUM", 0) * 5
            + severity_counts.get("LOW", 0) * 2
        )
        return round(max(0.0, min(100.0, 100.0 - penalty)), 1)
