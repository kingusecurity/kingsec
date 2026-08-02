"""Session-bound SQLAlchemy Assessment repository.

Receives an existing :class:`Session` — the caller (typically a Unit of Work)
owns the transaction.  This repository never commits, rolls back, or closes
the session.

Uses SQLAlchemy 2.x ``select()`` style and delegates ORM↔domain translation
to the existing ``mappers`` module.
"""

from __future__ import annotations

import builtins

from sqlalchemy import func, or_, select
from sqlalchemy.orm import Session

from kingsec.application import AssessmentNotFoundError, AssessmentRepository
from kingsec.application.ports.repositories import FindingProjection
from kingsec.domain import Assessment, AssessmentId
from kingsec.infrastructure.persistence.mappers import (
    assessment_to_domain,
    assessment_to_orm,
)
from kingsec.infrastructure.persistence.models import AssessmentORM, FindingORM

_ALLOWED_FINDING_ORDER_COLS = frozenset({
    "discovered_at",
    "severity",
    "status",
    "title",
})


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
    ) -> builtins.list[Assessment]:
        stmt = select(AssessmentORM).order_by(AssessmentORM.created_at.desc()).offset(offset).limit(limit)
        orms = self._session.execute(stmt).scalars().all()
        return [assessment_to_domain(o) for o in orms]

    def search_findings(
        self,
        *,
        severity: str | None = None,
        status: str | None = None,
        assessment_id: str | None = None,
        search: str | None = None,
        order_by: str = "discovered_at",
        order_dir: str = "desc",
        limit: int = 50,
        offset: int = 0,
    ) -> tuple[builtins.list[FindingProjection], int]:
        base = select(FindingORM, AssessmentORM.target_value).join(
            AssessmentORM, FindingORM.assessment_id == AssessmentORM.id
        )
        count_base = (
            select(func.count())
            .select_from(FindingORM)
            .join(AssessmentORM, FindingORM.assessment_id == AssessmentORM.id)
        )
        filters = []
        if severity:
            filters.append(FindingORM.severity == severity.upper())
        if status:
            filters.append(FindingORM.status == status.lower())
        if assessment_id:
            filters.append(FindingORM.assessment_id == assessment_id)
        if search:
            like = f"%{search}%"
            filters.append(or_(FindingORM.title.ilike(like), FindingORM.description.ilike(like)))
        if filters:
            base = base.where(*filters)
            count_base = count_base.where(*filters)

        order_col_name = order_by if order_by in _ALLOWED_FINDING_ORDER_COLS else "discovered_at"
        order_col = getattr(FindingORM, order_col_name, FindingORM.discovered_at)
        order_fn = order_col.desc if order_dir == "desc" else order_col.asc
        base = base.order_by(order_fn()).offset(offset).limit(limit)

        rows = self._session.execute(base).all()
        total = self._session.execute(count_base).scalar() or 0

        projections = []
        for orm, target in rows:
            projections.append(
                FindingProjection(
                    finding_id=orm.id,
                    assessment_id=orm.assessment_id,
                    target=target,
                    title=orm.title,
                    description=orm.description,
                    severity=orm.severity,
                    status=orm.status,
                    discovered_at=orm.discovered_at,
                    evidence_count=len(orm.evidence) if orm.evidence else 0,
                    recommendation_count=len(orm.recommendations) if orm.recommendations else 0,
                )
            )
        return projections, total

    def delete(self, assessment_id: AssessmentId) -> None:
        orm = self._session.get(AssessmentORM, assessment_id.value)
        if orm is None:
            raise AssessmentNotFoundError(assessment_id.value)
        self._session.delete(orm)
