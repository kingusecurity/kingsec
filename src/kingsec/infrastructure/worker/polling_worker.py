from __future__ import annotations

import threading
import time
from datetime import UTC, datetime

from kingsec.application.ports.job_service import JobServicePort
from kingsec.application.ports.outbound import WorkerServicePort
from kingsec.domain.worker import WorkerHeartbeat, WorkerId, WorkerStatus
from kingsec.infrastructure.logging import get_logger

_logger = get_logger("kingsec.infrastructure.worker.polling_worker")


class PollingWorkerService(WorkerServicePort):
    """A polling-based worker that processes jobs on a background thread.

    The worker polls for the oldest PENDING job at a configurable interval,
    transitions it to RUNNING, and then immediately to COMPLETED (the actual
    scan execution is delegated to a caller-provided callback).
    """

    def __init__(
        self,
        job_service: JobServicePort,
        worker_id: WorkerId | None = None,
        poll_interval_seconds: int = 5,
        heartbeat_interval_seconds: int = 30,
        max_jobs_per_run: int = 1,
    ) -> None:
        self._job_service = job_service
        self._worker_id = worker_id or WorkerId("default-worker")
        self._poll_interval = poll_interval_seconds
        self._heartbeat_interval = heartbeat_interval_seconds
        self._max_jobs_per_run = max_jobs_per_run

        self._status = WorkerStatus.STOPPED
        self._current_job_id: str | None = None
        self._jobs_completed = 0
        self._jobs_failed = 0
        self._start_time: float | None = None
        self._stop_requested = False
        self._stop_event = threading.Event()
        self._thread: threading.Thread | None = None
        self._lock = threading.Lock()

    def start_worker(self) -> None:
        with self._lock:
            if self._status == WorkerStatus.RUNNING:
                return
            self._status = WorkerStatus.RUNNING
            self._stop_requested = False
            self._start_time = time.monotonic()

        self._stop_event.clear()
        self._thread = threading.Thread(target=self._run_loop, daemon=True)
        self._thread.start()

    def stop_worker(self) -> None:
        self._stop_event.set()
        with self._lock:
            self._stop_requested = True
            self._status = WorkerStatus.STOPPED

    def execute_next_job(self) -> str | None:
        job = self._job_service.find_oldest_pending()
        if job is None:
            return None

        job_id = job.id.value
        try:
            self._job_service.transition_job(job_id, "RUNNING")
        except Exception:
            _logger.exception("failed to transition job to RUNNING", job_id=job_id)
            return None

        with self._lock:
            self._current_job_id = job_id

        try:
            self._run_job(job_id)
        except Exception:
            _logger.exception("job execution failed", job_id=job_id)
            with self._lock:
                self._jobs_failed += 1
                self._current_job_id = None
            return job_id

        with self._lock:
            self._jobs_completed += 1
            self._current_job_id = None
        return job_id

    def _run_job(self, job_id: str) -> None:
        self._job_service.transition_job(job_id, "COMPLETED")

    def heartbeat(self) -> WorkerHeartbeat:
        now = datetime.now(UTC).isoformat()
        time.monotonic() - (self._start_time or time.monotonic())
        with self._lock:
            return WorkerHeartbeat(
                worker_id=self._worker_id,
                status=self._status,
                timestamp=now,
                current_job_id=self._current_job_id,
                jobs_completed=self._jobs_completed,
                jobs_failed=self._jobs_failed,
            )

    def status(self) -> WorkerStatus:
        with self._lock:
            return self._status

    def _run_loop(self) -> None:
        while not self._stop_event.is_set():
            for _ in range(self._max_jobs_per_run):
                if self._stop_event.is_set():
                    break
                self.execute_next_job()
            self._stop_event.wait(self._poll_interval)
