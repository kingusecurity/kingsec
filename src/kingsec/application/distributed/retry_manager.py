"""Retry policy and dead letter queue management."""

from __future__ import annotations

from uuid import uuid4

from kingsec.application.distributed.ports import DeadLetterRepositoryPort, JobQueueRepositoryPort
from kingsec.domain.job import DeadLetterEntry, JobQueueEntry, JobState


class RetryManager:
    def __init__(
        self,
        queue_repo: JobQueueRepositoryPort,
        dead_letter_repo: DeadLetterRepositoryPort,
        max_retries: int = 3,
    ) -> None:
        self._queue_repo = queue_repo
        self._dead_letter_repo = dead_letter_repo
        self._max_retries = max_retries

    def handle_failure(self, entry_id: str, error_message: str = "") -> JobQueueEntry:
        entry = self._queue_repo.get(entry_id)
        if not entry:
            raise ValueError(f"Queue entry '{entry_id}' not found")
        if entry.retry_count < self._max_retries:
            retried = entry.mark_retrying()
            self._queue_repo.update(retried)
            return retried
        failed = entry.mark_failed(error_message)
        self._queue_repo.update(failed)
        dead = DeadLetterEntry(
            entry_id=f"dl-{uuid4().hex[:12]}",
            original_job_id=entry.job_id,
            original_entry_id=entry.entry_id,
            reason=error_message or "Max retries exceeded",
            payload=entry.payload,
            target=entry.target,
            retry_count=entry.retry_count,
        )
        self._dead_letter_repo.push(dead)
        return failed

    def retry_job(self, entry_id: str) -> JobQueueEntry:
        entry = self._queue_repo.get(entry_id)
        if not entry:
            raise ValueError(f"Queue entry '{entry_id}' not found")
        retried = entry.mark_retrying()
        self._queue_repo.update(retried)
        return retried

    def cancel_job(self, entry_id: str) -> JobQueueEntry:
        entry = self._queue_repo.get(entry_id)
        if not entry:
            raise ValueError(f"Queue entry '{entry_id}' not found")
        cancelled = entry.mark_cancelled()
        self._queue_repo.update(cancelled)
        return cancelled


class DeadLetterService:
    def __init__(self, repo: DeadLetterRepositoryPort, queue_repo: JobQueueRepositoryPort) -> None:
        self._repo = repo
        self._queue_repo = queue_repo

    def list(self) -> list[DeadLetterEntry]:
        return self._repo.find_all()

    def count(self) -> int:
        return self._repo.count()

    def requeue(self, entry_id: str) -> JobQueueEntry:
        entry = self._repo.get(entry_id)
        if not entry:
            raise ValueError(f"Dead letter entry '{entry_id}' not found")
        new_entry = JobQueueEntry(
            entry_id=f"jq-{uuid4().hex[:12]}",
            job_id=entry.original_job_id,
            state=JobState.QUEUED,
            payload=entry.payload,
            target=entry.target,
        )
        self._queue_repo.enqueue(new_entry)
        self._repo.delete(entry_id)
        return new_entry
