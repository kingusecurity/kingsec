"""Session-bound SQLAlchemy AuthorizationGrant repository (Phase 4).

Receives an existing :class:`Session` — the caller (typically a Unit of Work)
owns the transaction. This repository never commits, rolls back, or closes
the session. Mirrors SQLAlchemyAssessmentRepository's own shape exactly.
"""

from __future__ import annotations

import builtins
from datetime import datetime

from sqlalchemy import select
from sqlalchemy.orm import Session

from kingsec.application.errors import AuthorizationGrantNotFoundError
from kingsec.application.ports import AuthorizationGrantRepository
from kingsec.domain import AuthorizationGrant
from kingsec.domain.identifiers import AuthorizationGrantId
from kingsec.infrastructure.persistence.mappers import authorization_grant_to_domain, authorization_grant_to_orm
from kingsec.infrastructure.persistence.models import AuthorizationGrantORM


class SQLAlchemyAuthorizationGrantRepository(AuthorizationGrantRepository):
    """Implements :class:`AuthorizationGrantRepository` on a caller-owned session."""

    def __init__(self, session: Session) -> None:
        self._session = session

    def save(self, grant: AuthorizationGrant) -> None:
        existing = self._session.get(AuthorizationGrantORM, grant.id.value)
        orm = authorization_grant_to_orm(grant)
        if existing is None:
            self._session.add(orm)
        else:
            self._session.merge(orm)

    def get(self, grant_id: AuthorizationGrantId) -> AuthorizationGrant:
        orm = self._session.get(AuthorizationGrantORM, grant_id.value)
        if orm is None:
            raise AuthorizationGrantNotFoundError(grant_id.value)
        return authorization_grant_to_domain(orm)

    def list(self, *, limit: int = 50, offset: int = 0) -> builtins.list[AuthorizationGrant]:
        stmt = (
            select(AuthorizationGrantORM)
            .order_by(AuthorizationGrantORM.valid_from.desc())
            .offset(offset)
            .limit(limit)
        )
        orms = self._session.execute(stmt).scalars().all()
        return [authorization_grant_to_domain(o) for o in orms]

    def find_active(self, at: datetime) -> builtins.list[AuthorizationGrant]:
        # Filtered entirely in Python via is_active(), never a SQL-level
        # timestamp range comparison: valid_from/valid_until are stored as
        # ISO-8601 strings, and AuthorizationGrant only requires
        # timezone-AWARE (not specifically UTC) - a non-UTC offset would
        # sort incorrectly under lexicographic string comparison, silently
        # excluding a genuinely active grant from a SQL WHERE clause.
        # Grant volume is small (organizational, not per-scan), so loading
        # every row costs nothing meaningful here.
        stmt = select(AuthorizationGrantORM)
        orms = self._session.execute(stmt).scalars().all()
        candidates = [authorization_grant_to_domain(o) for o in orms]
        return [g for g in candidates if g.is_active(at)]

    def revoke(self, grant_id: AuthorizationGrantId, revoked_at: datetime) -> None:
        orm = self._session.get(AuthorizationGrantORM, grant_id.value)
        if orm is None:
            raise AuthorizationGrantNotFoundError(grant_id.value)
        orm.revoked_at = revoked_at.isoformat()
