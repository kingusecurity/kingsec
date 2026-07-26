"""Session-bound SQLAlchemy Report repository.

Receives an existing :class:`Session` — the caller owns the transaction.
This repository never commits, rolls back, or closes the session.
"""

from __future__ import annotations

from sqlalchemy import func, select
from sqlalchemy.orm import Session

from kingsec.application import ReportNotFoundError, ReportRepository
from kingsec.application.ports.repositories import ReportProjection
from kingsec.domain import AssessmentId, Report
from kingsec.infrastructure.persistence.mappers import report_to_domain, report_to_orm
from kingsec.infrastructure.persistence.models import ReportORM


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
    ) -> tuple[list[ReportProjection], int]:
        order_col = getattr(ReportORM, order_by, ReportORM.generated_at)
        order_fn = order_col.desc if order_dir == "desc" else order_col.asc
        stmt = (
            select(ReportORM)
            .order_by(order_fn())
            .offset(offset)
            .limit(limit)
        )
        orms = self._session.execute(stmt).scalars().all()
        total = self._session.execute(select(func.count()).select_from(ReportORM)).scalar() or 0
        projections = []
        for orm in orms:
            projections.append(
                ReportProjection(
                    assessment_id=orm.assessment_id,
                    target=orm.target,
                    generated_at=orm.generated_at,
                    verdict_headline=orm.verdict_headline,
                    verdict_highest_severity=orm.verdict_highest_severity,
                    verdict_action_required=orm.verdict_action_required,
                    total_findings=len(orm.entries),
                    format="pdf",
                    file_size=0,
                )
            )
        return projections, total

    def count(self) -> int:
        return self._session.execute(select(func.count()).select_from(ReportORM)).scalar() or 0
