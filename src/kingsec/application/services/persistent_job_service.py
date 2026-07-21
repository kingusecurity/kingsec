"""Persistence-backed ``JobServicePort`` implementation.

Every operation executes through an injected ``UnitOfWorkPort``, so all
reads and writes share a consistent transactional boundary.  The service
never accesses SQLAlchemy, never creates sessions, and never creates
repositories — it delegates all persistence to the Unit of Work.
"""

from __future__ import annotations

import uuid
from datetime import UTC, datetime
from typing import Any

from kingsec.application.errors import IllegalJobTransitionError
from kingsec.application.job import JobId
from kingsec.application.jobs import (
    JobStatus,
    ScanJob,
    ScanJobResult,
    validate_transition,
)
from kingsec.application.ports.job_service import JobServicePort
from kingsec.application.unit_of_work import UnitOfWorkPort


class PersistentJobService(JobServicePort):
    """``JobServicePort`` backed by a ``UnitOfWorkPort``.

    Each public method wraps its work in a fresh Unit of Work transaction:

        with self._uow:
            ... self._uow.job_repository.xxx ...
            self._uow.commit()

    On success the transaction is committed.  On any exception the UoW
    automatically rolls back (per the port contract).
    """

    def __init__(self, uow: UnitOfWorkPort) -> None:
        self._uow = uow

    def submit_scan(self, target: str, config: dict[str, Any] | None = None) -> ScanJob:
        job_id = JobId(str(uuid.uuid4()))
        now = datetime.now(UTC)
        job = ScanJob(
            id=job_id,
            target=target,
            config=config or {},
            status=JobStatus.PENDING,
            created_at=now,
            updated_at=now,
        )
        with self._uow:
            self._uow.job_repository.save(job)
            self._uow.commit()
        return job

    def get_job(self, job_id: str) -> ScanJob:
        with self._uow:
            job = self._uow.job_repository.get(job_id)
            self._uow.commit()
        return job

    def list_jobs(self) -> list[ScanJob]:
        with self._uow:
            jobs = self._uow.job_repository.list()
            self._uow.commit()
        return jobs

    def cancel_job(self, job_id: str) -> ScanJob:
        with self._uow:
            job = self._uow.job_repository.get(job_id)
            validate_transition(job.status, JobStatus.CANCELLED)
            now = datetime.now(UTC)
            updated = ScanJob(
                id=job.id,
                target=job.target,
                config=job.config,
                status=JobStatus.CANCELLED,
                created_at=job.created_at,
                updated_at=now,
            )
            self._uow.job_repository.save(updated)
            self._uow.commit()
        return updated

    def transition_job(self, job_id: str, target_status: str) -> ScanJob:
        target = JobStatus(target_status)
        with self._uow:
            job = self._uow.job_repository.get(job_id)
            validate_transition(job.status, target)
            now = datetime.now(UTC)
            updated = ScanJob(
                id=job.id,
                target=job.target,
                config=job.config,
                status=target,
                created_at=job.created_at,
                updated_at=now,
            )
            self._uow.job_repository.save(updated)
            self._uow.commit()
        return updated

    def find_oldest_pending(self) -> ScanJob | None:
        with self._uow:
            jobs = self._uow.job_repository.list()
            self._uow.commit()
        pending = [j for j in jobs if j.status == JobStatus.PENDING]
        if not pending:
            return None
        return min(pending, key=lambda j: j.created_at)

    def get_job_result(self, job_id: str) -> ScanJobResult:
        with self._uow:
            job = self._uow.job_repository.get(job_id)
            self._uow.commit()
        if job.status != JobStatus.COMPLETED:
            raise IllegalJobTransitionError(f"Job {job_id} has status {job.status.value}, not COMPLETED")
        return ScanJobResult(
            job_id=job_id,
            completed_at=job.updated_at,
        )
