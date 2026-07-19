from __future__ import annotations

import threading
import uuid
from dataclasses import dataclass
from datetime import UTC, datetime
from enum import Enum

from kingsec.application.errors import IllegalJobTransitionError, JobNotFoundError
from kingsec.application.job import JobId
from kingsec.application.ports.job_service import JobServicePort


class JobStatus(Enum):
    """Lifecycle states for a scan job.

    Valid transitions::

        PENDING → RUNNING → COMPLETED
                          → FAILED
                          → CANCELLED

    Terminal states: COMPLETED, FAILED, CANCELLED
    """

    PENDING = "PENDING"
    RUNNING = "RUNNING"
    COMPLETED = "COMPLETED"
    FAILED = "FAILED"
    CANCELLED = "CANCELLED"

    @property
    def is_terminal(self) -> bool:
        return self in (JobStatus.COMPLETED, JobStatus.FAILED, JobStatus.CANCELLED)


_TRANSITIONS: dict[JobStatus, set[JobStatus]] = {
    JobStatus.PENDING: {JobStatus.RUNNING, JobStatus.CANCELLED},
    JobStatus.RUNNING: {JobStatus.COMPLETED, JobStatus.FAILED, JobStatus.CANCELLED},
    JobStatus.COMPLETED: set(),
    JobStatus.FAILED: set(),
    JobStatus.CANCELLED: set(),
}


def validate_transition(current: JobStatus, target: JobStatus) -> None:
    """Check whether *target* is reachable from *current*.

    Raises ``IllegalJobTransitionError`` if not.
    """
    if target not in _TRANSITIONS.get(current, set()):
        raise IllegalJobTransitionError(
            f"Cannot transition from {current.value} to {target.value}"
        )


@dataclass(frozen=True)
class ScanJob:
    """A scan job queued for asynchronous execution."""

    id: JobId
    target: str
    config: dict
    status: JobStatus
    created_at: datetime
    updated_at: datetime


@dataclass(frozen=True)
class ScanJobResult:
    """The output of a completed scan job."""

    job_id: str
    completed_at: datetime
    findings: tuple[dict, ...] = ()
    error: str | None = None


class InMemoryJobService(JobServicePort):
    """Thread-safe in-memory job service for development and testing.

    No background queues, no external dependencies.  Jobs are stored
    in dicts guarded by a ``threading.Lock``.
    """

    def __init__(self) -> None:
        self._jobs: dict[str, ScanJob] = {}
        self._results: dict[str, ScanJobResult] = {}
        self._lock = threading.Lock()

    # ------------------------------------------------------------------
    # Port interface
    # ------------------------------------------------------------------

    def submit_scan(self, target: str, config: dict | None = None) -> ScanJob:
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
        with self._lock:
            self._jobs[job_id.value] = job
        return job

    def get_job(self, job_id: str) -> ScanJob:
        with self._lock:
            job = self._jobs.get(job_id)
        if job is None:
            raise JobNotFoundError(f"Job not found: {job_id}")
        return job

    def list_jobs(self) -> list[ScanJob]:
        with self._lock:
            jobs = list(self._jobs.values())
        jobs.sort(key=lambda j: j.created_at, reverse=True)
        return jobs

    def cancel_job(self, job_id: str) -> ScanJob:
        with self._lock:
            job = self._jobs.get(job_id)
            if job is None:
                raise JobNotFoundError(f"Job not found: {job_id}")
            validate_transition(job.status, JobStatus.CANCELLED)
            now = datetime.now(UTC)
            job = ScanJob(
                id=job.id,
                target=job.target,
                config=job.config,
                status=JobStatus.CANCELLED,
                created_at=job.created_at,
                updated_at=now,
            )
            self._jobs[job_id] = job
        return job

    def get_job_result(self, job_id: str) -> ScanJobResult:
        with self._lock:
            job = self._jobs.get(job_id)
            if job is None:
                raise JobNotFoundError(f"Job not found: {job_id}")
            if job.status != JobStatus.COMPLETED:
                raise IllegalJobTransitionError(
                    f"Job {job_id} has status {job.status.value}, not COMPLETED"
                )
            result = self._results.get(job_id)
        if result is None:
            raise JobNotFoundError(f"No result for job: {job_id}")
        return result

    # ------------------------------------------------------------------
    # Helpers for testing / development
    # ------------------------------------------------------------------

    def transition_job(self, job_id: str, target: JobStatus) -> ScanJob:
        """Transition a job to *target* (raises if illegal).

        This is intentionally NOT part of the port — it exists to support
        testing and manual state machine exploration without a background
        worker.
        """
        with self._lock:
            job = self._jobs.get(job_id)
            if job is None:
                raise JobNotFoundError(f"Job not found: {job_id}")
            validate_transition(job.status, target)
            now = datetime.now(UTC)
            job = ScanJob(
                id=job.id,
                target=job.target,
                config=job.config,
                status=target,
                created_at=job.created_at,
                updated_at=now,
            )
            self._jobs[job_id] = job
        return job

    def store_result(self, job_id: str, result: ScanJobResult) -> None:
        """Associate a result with a job.

        The job must already be in COMPLETED (or FAILED) state.
        """
        with self._lock:
            self._results[job_id] = result
