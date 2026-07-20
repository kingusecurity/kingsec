"""Port for the worker engine — no infrastructure imports."""

from __future__ import annotations

from abc import ABC, abstractmethod

from kingsec.domain.worker import WorkerHeartbeat, WorkerStatus


class WorkerServicePort(ABC):
    @abstractmethod
    def start_worker(self) -> None:
        ...

    @abstractmethod
    def stop_worker(self) -> None:
        ...

    @abstractmethod
    def execute_next_job(self) -> str | None:
        ...

    @abstractmethod
    def heartbeat(self) -> WorkerHeartbeat:
        ...

    @abstractmethod
    def status(self) -> WorkerStatus:
        ...
