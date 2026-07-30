"""Worker registration, heartbeat, and lifecycle management."""

from __future__ import annotations

from collections.abc import Callable
from datetime import UTC, datetime

from kingsec.application.distributed.ports import (
    DeadLetterRepositoryPort,
    JobLeaseRepositoryPort,
    JobQueueRepositoryPort,
    WorkerRepositoryPort,
)
from kingsec.application.errors import WorkerNotFoundError
from kingsec.domain.job import DeadLetterEntry, JobQueueEntry, WorkerCapability, WorkerNode, WorkerStatus


class WorkerRegistrationService:
    def __init__(self, repo: WorkerRepositoryPort) -> None:
        self._repo = repo

    def register(
        self,
        worker_id: str,
        hostname: str,
        os: str,
        cpu: str,
        ram_mb: int,
        capabilities: list[dict[str, str]] | None = None,
    ) -> WorkerNode:
        caps = tuple(
            WorkerCapability(
                scanner_id=c["scanner_id"],
                scanner_name=c.get("scanner_name", c["scanner_id"]),
                scanner_version=c.get("scanner_version", "0.0.0"),
            )
            for c in (capabilities or [])
        )
        worker = WorkerNode(
            worker_id=worker_id,
            hostname=hostname,
            os=os,
            cpu=cpu,
            ram_mb=ram_mb,
            capabilities=caps,
            last_heartbeat=datetime.now(UTC).isoformat(),
            status=WorkerStatus.ONLINE,
            health="healthy",
        )
        existing = self._repo.get(worker_id)
        if existing:
            worker = WorkerNode(
                worker_id=worker_id,
                hostname=hostname,
                os=os,
                cpu=cpu,
                ram_mb=ram_mb,
                capabilities=caps,
                current_jobs=existing.current_jobs,
                last_heartbeat=datetime.now(UTC).isoformat(),
                status=WorkerStatus.ONLINE,
                health="healthy",
                created_at=existing.created_at,
            )
            self._repo.update(worker)
        else:
            worker = self._repo.register(worker)
        return worker

    def get(self, worker_id: str) -> WorkerNode:
        worker = self._repo.get(worker_id)
        if not worker:
            raise WorkerNotFoundError(f"Worker '{worker_id}' not found")
        return worker

    def list_all(self) -> list[WorkerNode]:
        return self._repo.find_all()

    def delete(self, worker_id: str) -> None:
        worker = self._repo.get(worker_id)
        if not worker:
            raise WorkerNotFoundError(f"Worker '{worker_id}' not found")
        self._repo.delete(worker_id)


class HeartbeatManager:
    def __init__(
        self,
        worker_repo: WorkerRepositoryPort,
        job_queue_repo: JobQueueRepositoryPort,
        lease_repo: JobLeaseRepositoryPort,
        dead_letter_repo: DeadLetterRepositoryPort,
        heartbeat_timeout_seconds: int = 30,
        clock: Callable[[], str] | None = None,
    ) -> None:
        self._worker_repo = worker_repo
        self._job_queue_repo = job_queue_repo
        self._lease_repo = lease_repo
        self._dead_letter_repo = dead_letter_repo
        self._heartbeat_timeout = heartbeat_timeout_seconds
        self._clock = clock or (lambda: datetime.now(UTC).isoformat())

    def process_heartbeat(
        self,
        worker_id: str,
        status: str = "online",
        current_jobs: list[str] | None = None,
        health: str = "healthy",
    ) -> WorkerNode:
        worker = self._worker_repo.get(worker_id)
        if not worker:
            raise WorkerNotFoundError(f"Worker '{worker_id}' not found")
        ws = WorkerStatus.ONLINE if status == "online" else WorkerStatus.BUSY if status == "busy" else WorkerStatus.DEGRADED
        updated = worker.update_heartbeat(
            status=ws,
            current_jobs=tuple(current_jobs or []),
            health=health,
        )
        self._worker_repo.update(updated)
        return updated

    def mark_stale_workers_offline(self) -> list[WorkerNode]:
        now = datetime.now(UTC)
        stale: list[WorkerNode] = []
        for worker in self._worker_repo.find_online():
            if not worker.last_heartbeat:
                continue
            try:
                hb_time = datetime.fromisoformat(worker.last_heartbeat)
            except ValueError:
                continue
            if (now - hb_time).total_seconds() > self._heartbeat_timeout:
                offline = worker.mark_offline()
                self._worker_repo.update(offline)
                stale.append(offline)
                self._reassign_abandoned_jobs(worker.worker_id)
        return stale

    def _reassign_abandoned_jobs(self, worker_id: str) -> None:
        leases = self._lease_repo.find_by_worker(worker_id)
        for lease in leases:
            entry = self._job_queue_repo.get(lease.job_id)
            if entry and entry.state.value in ("assigned", "running"):
                self._lease_repo.delete(lease.lease_id)
                retried = entry.mark_retrying()
                self._job_queue_repo.update(retried)
                if retried.retry_count >= retried.max_retries:
                    failed = retried.mark_failed("Max retries exceeded after worker went offline")
                    self._job_queue_repo.update(failed)
                    dead = _build_dead_letter(failed, "Worker went offline and max retries exceeded")
                    self._dead_letter_repo.push(dead)


def _build_dead_letter(entry: JobQueueEntry, reason: str) -> DeadLetterEntry:
    return DeadLetterEntry(
        entry_id=f"dl-{entry.entry_id}",
        original_job_id=entry.job_id,
        original_entry_id=entry.entry_id,
        reason=reason,
        payload=entry.payload,
        target=entry.target,
        retry_count=entry.retry_count,
        failed_at=datetime.now(UTC).isoformat(),
    )
