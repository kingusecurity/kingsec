"""Job dispatch, lease management, and coordination."""

from __future__ import annotations

from datetime import UTC, datetime
from uuid import uuid4

from kingsec.application.distributed.ports import (
    DeadLetterRepositoryPort,
    JobLeaseRepositoryPort,
    JobQueueRepositoryPort,
    WorkerRepositoryPort,
)
from kingsec.application.distributed.scheduler import SchedulingStrategy
from kingsec.application.errors import DuplicateJobAssignmentError, JobLeaseExpiredError, JobLeaseNotFoundError, WorkerOfflineError
from kingsec.domain.job import DeadLetterEntry, JobLease, JobQueueEntry, JobState, WorkerNode, WorkerStatus


class JobLeaseManager:
    def __init__(self, lease_repo: JobLeaseRepositoryPort, queue_repo: JobQueueRepositoryPort, ttl_seconds: int = 120) -> None:
        self._lease_repo = lease_repo
        self._queue_repo = queue_repo
        self._ttl = ttl_seconds

    def acquire(self, job_id: str, worker_id: str) -> JobLease:
        entry = self._queue_repo.get(job_id)
        if not entry:
            raise JobLeaseNotFoundError(f"Job '{job_id}' not found")
        if entry.state in (JobState.COMPLETED, JobState.CANCELLED, JobState.EXPIRED):
            raise DuplicateJobAssignmentError(f"Job '{job_id}' is already {entry.state.value}")
        existing = self._lease_repo.find_by_job(job_id)
        if existing and not existing.is_expired():
            raise DuplicateJobAssignmentError(f"Job '{job_id}' already has an active lease for worker '{existing.worker_id}'")
        if existing:
            self._lease_repo.delete(existing.lease_id)
        now = datetime.now(UTC)
        lease = JobLease(
            lease_id=str(uuid4()),
            job_id=job_id,
            worker_id=worker_id,
            acquired_at=now.isoformat(),
            expires_at=now.isoformat(),
        )
        assigned = entry.assign(worker_id)
        self._queue_repo.update(assigned)
        return self._lease_repo.create(lease)

    def renew(self, lease_id: str) -> JobLease:
        lease = self._lease_repo.get(lease_id)
        if not lease:
            raise JobLeaseNotFoundError(f"Lease '{lease_id}' not found")
        renewed = lease.renew(self._ttl)
        self._lease_repo.update(renewed)
        return renewed

    def release(self, lease_id: str) -> None:
        lease = self._lease_repo.get(lease_id)
        if not lease:
            raise JobLeaseNotFoundError(f"Lease '{lease_id}' not found")
        released = lease.release()
        self._lease_repo.update(released)

    def expire_stale_leases(self) -> list[JobLease]:
        expired = self._lease_repo.find_expired()
        for lease in expired:
            entry = self._queue_repo.get(lease.job_id)
            if entry:
                expired_entry = entry.mark_expired()
                self._queue_repo.update(expired_entry)
            self._lease_repo.delete(lease.lease_id)
        return expired


class JobDispatcher:
    def __init__(
        self,
        queue_repo: JobQueueRepositoryPort,
        worker_repo: WorkerRepositoryPort,
        lease_manager: JobLeaseManager,
        scheduler: SchedulingStrategy,
        dead_letter_repo: DeadLetterRepositoryPort,
    ) -> None:
        self._queue_repo = queue_repo
        self._worker_repo = worker_repo
        self._lease_mgr = lease_manager
        self._scheduler = scheduler
        self._dead_letter_repo = dead_letter_repo

    def dispatch_next(self) -> JobQueueEntry | None:
        queued = self._queue_repo.find_queued()
        if not queued:
            return None
        workers = self._worker_repo.find_online()
        if not workers:
            return None
        for job in queued:
            worker = self._scheduler.select_worker(job, workers)
            if not worker:
                continue
            try:
                self._lease_mgr.acquire(job.job_id, worker.worker_id)
            except (DuplicateJobAssignmentError, JobLeaseNotFoundError):
                continue
            assigned = job.assign(worker.worker_id)
            self._queue_repo.update(assigned)
            return assigned
        return None

    def dispatch_retrying(self) -> list[JobQueueEntry]:
        retrying = self._queue_repo.find_retrying()
        dispatched: list[JobQueueEntry] = []
        workers = self._worker_repo.find_online()
        if not workers:
            return []
        for job in retrying:
            worker = self._scheduler.select_worker(job, workers)
            if not worker:
                continue
            assigned = job.assign(worker.worker_id)
            self._queue_repo.update(assigned)
            dispatched.append(assigned)
        return dispatched
