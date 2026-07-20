from __future__ import annotations

from kingsec.application.ports.outbound import WorkerServicePort
from kingsec.domain.worker import WorkerHeartbeat, WorkerStatus


class WorkerUseCase:
    """Orchestrate the worker lifecycle from higher-level application code."""

    def __init__(self, worker: WorkerServicePort) -> None:
        self._worker = worker

    def start(self) -> None:
        self._worker.start_worker()

    def stop(self) -> None:
        self._worker.stop_worker()

    def execute_next(self) -> str | None:
        return self._worker.execute_next_job()

    def status(self) -> WorkerStatus:
        return self._worker.status()

    def heartbeat(self) -> WorkerHeartbeat:
        return self._worker.heartbeat()
