"""Session-bound SQLAlchemy Assessment repository.

Receives an existing :class:`Session` — the caller (typically a Unit of Work)
owns the transaction.  This repository never commits, rolls back, or closes
the session.

Uses SQLAlchemy 2.x ``select()`` style and delegates ORM↔domain translation
to the existing ``mappers`` module.
"""

from __future__ import annotations

import builtins

from sqlalchemy import and_, func, or_, select
from sqlalchemy.orm import Session

from kingsec.application import AssessmentNotFoundError, AssessmentRepository
from kingsec.application.ports.repositories import FindingProjection
from kingsec.domain import Assessment, AssessmentId
from kingsec.infrastructure.persistence import _operations as ops
from kingsec.infrastructure.persistence.mappers import assessment_to_domain
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
        """Delegates to the shared, version-gated ``persist_assessment()``
        (KSEC-107-01 / KSEC-108-01) - previously this method carried its
        own, independent, unconditional DELETE-then-INSERT, a duplicate of
        (and until this phase, divergent from) the same logic already
        shared by ``LegacyAssessmentRepository``/
        ``_SessionBoundAssessmentRepository``. Consolidating onto one
        primitive means the optimistic-concurrency guarantee cannot
        silently regress in one Assessment repository implementation
        while being fixed in another."""
        ops.persist_assessment(self._session, assessment)

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

    def find_by_schedule_occurrence_id(self, occurrence_id: str) -> builtins.list[Assessment]:
        """Return every assessment linked to a schedule occurrence (KSEC-100-01)."""
        stmt = (
            select(AssessmentORM)
            .where(AssessmentORM.schedule_occurrence_id == occurrence_id)
            .order_by(AssessmentORM.created_at.asc())
        )
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
        requesting_user: str = "",
        is_admin: bool = False,
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
        if not is_admin:
            # Fail closed: only findings whose assessment is owned by the
            # caller are visible (legacy assessments with no owner recorded
            # are excluded too, matching get_assessment's fail-closed rule) —
            # mirrors check_assessment_access's "owner_id truthy and equal"
            # condition exactly.
            filters.append(
                and_(
                    AssessmentORM.owner_id.isnot(None),
                    AssessmentORM.owner_id != "",
                    AssessmentORM.owner_id == requesting_user,
                )
            )
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
