"""Session-bound SQLAlchemy Report repository.

Receives an existing :class:`Session` — the caller owns the transaction.
This repository never commits, rolls back, or closes the session.
"""

from __future__ import annotations

from sqlalchemy.orm import Session

from kingsec.application import ReportNotFoundError, ReportRepository
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
