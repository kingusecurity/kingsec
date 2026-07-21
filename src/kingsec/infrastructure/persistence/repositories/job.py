"""Session-bound SQLAlchemy Job repository.

Persists and retrieves :class:`ScanJob` records through the ``JobModel`` ORM model.
"""

from __future__ import annotations

from sqlalchemy import select
from sqlalchemy.orm import Session

from kingsec.application import JobNotFoundError, JobRepositoryPort
from kingsec.application.jobs import ScanJob
from kingsec.infrastructure.persistence.mappers import job_to_domain, job_to_orm
from kingsec.infrastructure.persistence.models import JobModel


class SQLAlchemyJobRepository(JobRepositoryPort):
    """Implements :class:`JobRepositoryPort` on a caller-owned session."""

    def __init__(self, session: Session) -> None:
        self._session = session

    def save(self, job: ScanJob) -> None:
        existing = self._session.get(JobModel, str(job.id))
        if existing is not None:
            self._session.delete(existing)
            self._session.flush()
        self._session.add(job_to_orm(job))

    def get(self, job_id: str) -> ScanJob:
        orm = self._session.get(JobModel, job_id)
        if orm is None:
            raise JobNotFoundError(job_id)
        return job_to_domain(orm)

    def list(
        self,
        *,
        limit: int = 50,
        offset: int = 0,
    ) -> list[ScanJob]:
        stmt = select(JobModel).order_by(JobModel.created_at.desc()).offset(offset).limit(limit)
        orms = self._session.execute(stmt).scalars().all()
        return [job_to_domain(o) for o in orms]

    def exists(self, job_id: str) -> bool:
        orm = self._session.get(JobModel, job_id)
        return orm is not None
