"""Thread-based job runner implementation.

Uses ``concurrent.futures.ThreadPoolExecutor`` to run callables in background
threads. Thread safety is ensured by:

* The executor itself is thread-safe (Python stdlib guarantee).
* Job status is protected by a ``threading.Lock``.
* Each background job receives a fresh assessment from the repository, so there
  is no shared mutable domain state between threads.

Shutdown
    ``shutdown(wait=True)`` is registered as a DI container shutdown hook so
    pending jobs complete before the process exits.
"""

from __future__ import annotations

import threading
from concurrent.futures import Future, ThreadPoolExecutor
from typing import Any

from kingsec.application.ports.outbound.job_runner import JobRunner
from kingsec.infrastructure.logging import get_logger

logger = get_logger(__name__)


class JobRunnerError(Exception):
    """Raised when a job cannot be submitted."""


class ThreadJobRunner(JobRunner):
    """Runs callables in background threads via a ThreadPoolExecutor."""

    def __init__(self, max_workers: int = 4) -> None:
        self._max_workers = max_workers
        self._executor = ThreadPoolExecutor(
            max_workers=max_workers,
            thread_name_prefix="kingsec-job",
        )
        self._futures: dict[str, Future[None]] = {}
        self._lock = threading.Lock()

    def submit(
        self,
        job_id: str,
        fn: Any,
        *args: Any,
        **kwargs: Any,
    ) -> None:
        """Submit a callable for background execution.

        Raises:
            JobRunnerError: If a job with this ID is already running.
        """
        with self._lock:
            if job_id in self._futures:
                future = self._futures[job_id]
                if not future.done():
                    raise JobRunnerError(
                        f"job {job_id!r} is already running"
                    )

            def _wrapper() -> None:
                logger.info("job started", job_id=job_id)
                try:
                    fn(*args, **kwargs)
                    logger.info("job completed", job_id=job_id)
                except Exception:
                    logger.exception("job failed", job_id=job_id)

            future = self._executor.submit(_wrapper)
            self._futures[job_id] = future

    def is_running(self, job_id: str) -> bool:
        """Return True if the job is still executing."""
        with self._lock:
            future = self._futures.get(job_id)
            if future is None:
                return False
            return not future.done()

    def shutdown(self, wait: bool = True) -> None:
        """Shutdown the executor, waiting for pending jobs if requested."""
        self._executor.shutdown(wait=wait)
        logger.info("job runner shut down", wait=wait)
