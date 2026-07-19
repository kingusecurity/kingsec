"""Session-bound SQLAlchemy Assessment repository.

Receives an existing :class:`Session` — the caller (typically a Unit of Work)
owns the transaction.  This repository never commits, rolls back, or closes
the session.

Uses SQLAlchemy 2.x ``select()`` style and delegates ORM↔domain translation
to the existing ``mappers`` module.
"""

from __future__ import annotations

from datetime import datetime

from sqlalchemy import select
from sqlalchemy.orm import Session

from kingsec.application import AssessmentNotFoundError, AssessmentRepository
from kingsec.domain import Assessment, AssessmentId
from kingsec.infrastructure.persistence.mappers import (
    assessment_to_domain,
    assessment_to_orm,
)
from kingsec.infrastructure.persistence.models import AssessmentORM


class SQLAlchemyAssessmentRepository(AssessmentRepository):
    """Implements :class:`AssessmentRepository` on a caller-owned session.

    No transaction management — the caller decides when to commit or roll back.
    """

    def __init__(self, session: Session) -> None:
        self._session = session

    def save(self, assessment: Assessment) -> None:
        existing = self._session.get(AssessmentORM, str(assessment.id))
        if existing is not None:
            self._session.delete(existing)
            self._session.flush()
        self._session.add(assessment_to_orm(assessment))

    def get(self, assessment_id: AssessmentId) -> Assessment:
        orm = self._session.get(AssessmentORM, assessment_id.value)
        if orm is None:
            raise AssessmentNotFoundError(assessment_id.value)
        return assessment_to_domain(orm)

    def list(
        self,
        *,
        limit: int = 50,
        offset: int = 0,
    ) -> list[Assessment]:
        stmt = (
            select(AssessmentORM)
            .order_by(AssessmentORM.created_at.desc())
            .offset(offset)
            .limit(limit)
        )
        orms = self._session.execute(stmt).scalars().all()
        return [assessment_to_domain(o) for o in orms]

    def delete(self, assessment_id: AssessmentId) -> None:
        orm = self._session.get(AssessmentORM, assessment_id.value)
        if orm is None:
            raise AssessmentNotFoundError(assessment_id.value)
        self._session.delete(orm)
