"""Repository ports for distributed worker infrastructure."""

from __future__ import annotations

from abc import ABC, abstractmethod

from kingsec.domain.job import DeadLetterEntry, JobLease, JobQueueEntry, QueueMetrics, WorkerNode


class WorkerRepositoryPort(ABC):
    @abstractmethod
    def register(self, worker: WorkerNode) -> WorkerNode: ...

    @abstractmethod
    def get(self, worker_id: str) -> WorkerNode | None: ...

    @abstractmethod
    def find_all(self) -> list[WorkerNode]: ...

    @abstractmethod
    def find_online(self) -> list[WorkerNode]: ...

    @abstractmethod
    def find_idle(self) -> list[WorkerNode]: ...

    @abstractmethod
    def update(self, worker: WorkerNode) -> None: ...

    @abstractmethod
    def delete(self, worker_id: str) -> None: ...


class JobQueueRepositoryPort(ABC):
    @abstractmethod
    def enqueue(self, entry: JobQueueEntry) -> JobQueueEntry: ...

    @abstractmethod
    def get(self, entry_id: str) -> JobQueueEntry | None: ...

    @abstractmethod
    def find_by_state(self, state: str) -> list[JobQueueEntry]: ...

    @abstractmethod
    def find_all(self) -> list[JobQueueEntry]: ...

    @abstractmethod
    def update(self, entry: JobQueueEntry) -> None: ...

    @abstractmethod
    def delete(self, entry_id: str) -> None: ...

    @abstractmethod
    def get_metrics(self) -> QueueMetrics: ...

    @abstractmethod
    def find_queued(self) -> list[JobQueueEntry]: ...

    @abstractmethod
    def find_assigned(self) -> list[JobQueueEntry]: ...

    @abstractmethod
    def find_retrying(self) -> list[JobQueueEntry]: ...

    @abstractmethod
    def find_expired(self) -> list[JobQueueEntry]: ...


class JobLeaseRepositoryPort(ABC):
    @abstractmethod
    def create(self, lease: JobLease) -> JobLease: ...

    @abstractmethod
    def get(self, lease_id: str) -> JobLease | None: ...

    @abstractmethod
    def find_by_job(self, job_id: str) -> JobLease | None: ...

    @abstractmethod
    def find_by_worker(self, worker_id: str) -> list[JobLease]: ...

    @abstractmethod
    def find_expired(self) -> list[JobLease]: ...

    @abstractmethod
    def update(self, lease: JobLease) -> None: ...

    @abstractmethod
    def delete(self, lease_id: str) -> None: ...


class DeadLetterRepositoryPort(ABC):
    @abstractmethod
    def push(self, entry: DeadLetterEntry) -> DeadLetterEntry: ...

    @abstractmethod
    def get(self, entry_id: str) -> DeadLetterEntry | None: ...

    @abstractmethod
    def find_all(self) -> list[DeadLetterEntry]: ...

    @abstractmethod
    def delete(self, entry_id: str) -> None: ...

    @abstractmethod
    def count(self) -> int: ...
