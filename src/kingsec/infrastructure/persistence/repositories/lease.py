"""SQLAlchemy-backed JobLeaseRepositoryPort."""

from __future__ import annotations

from collections.abc import Callable
from datetime import UTC, datetime

from sqlalchemy import select
from sqlalchemy.orm import Session

from kingsec.application.distributed.ports import JobLeaseRepositoryPort
from kingsec.domain.job import JobLease
from kingsec.infrastructure.persistence.mappers import job_lease_to_domain, job_lease_to_orm
from kingsec.infrastructure.persistence.models import JobLeaseModel


class SQLAlchemyJobLeaseRepository(JobLeaseRepositoryPort):
    def __init__(self, session_factory: Callable[[], Session]) -> None:
        self._session_factory = session_factory

    def create(self, lease: JobLease) -> JobLease:
        orm = job_lease_to_orm(lease)
        with self._session_factory() as session:
            session.add(orm)
            session.commit()
            return lease

    def get(self, lease_id: str) -> JobLease | None:
        stmt = select(JobLeaseModel).where(JobLeaseModel.lease_id == lease_id)
        with self._session_factory() as session:
            orm = session.execute(stmt).scalar_one_or_none()
            return job_lease_to_domain(orm) if orm else None

    def find_by_job(self, job_id: str) -> JobLease | None:
        stmt = select(JobLeaseModel).where(JobLeaseModel.job_id == job_id)
        with self._session_factory() as session:
            orm = session.execute(stmt).scalar_one_or_none()
            return job_lease_to_domain(orm) if orm else None

    def find_by_worker(self, worker_id: str) -> list[JobLease]:
        stmt = select(JobLeaseModel).where(JobLeaseModel.worker_id == worker_id)
        with self._session_factory() as session:
            rows = session.execute(stmt).scalars().all()
            return [job_lease_to_domain(r) for r in rows]

    def find_expired(self) -> list[JobLease]:
        now = datetime.now(UTC).isoformat()
        stmt = select(JobLeaseModel).where(
            JobLeaseModel.expires_at < now,
            JobLeaseModel.released_at.is_(None),
        )
        with self._session_factory() as session:
            rows = session.execute(stmt).scalars().all()
            return [job_lease_to_domain(r) for r in rows]

    def update(self, lease: JobLease) -> None:
        orm = job_lease_to_orm(lease)
        with self._session_factory() as session:
            session.merge(orm)
            session.commit()

    def delete(self, lease_id: str) -> None:
        stmt = select(JobLeaseModel).where(JobLeaseModel.lease_id == lease_id)
        with self._session_factory() as session:
            orm = session.execute(stmt).scalar_one_or_none()
            if orm:
                session.delete(orm)
                session.commit()
