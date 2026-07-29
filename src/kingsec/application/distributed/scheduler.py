"""Scheduling strategies for job-to-worker assignment."""

from __future__ import annotations

from abc import ABC, abstractmethod
from typing import Callable

from kingsec.domain.job import JobQueueEntry, WorkerNode, WorkerStatus


class SchedulingStrategy(ABC):
    @abstractmethod
    def select_worker(self, job: JobQueueEntry, workers: list[WorkerNode]) -> WorkerNode | None: ...


class RoundRobinScheduler(SchedulingStrategy):
    def __init__(self) -> None:
        self._index: dict[str, int] = {}

    def select_worker(self, job: JobQueueEntry, workers: list[WorkerNode]) -> WorkerNode | None:
        if not workers:
            return None
        key = "default"
        idx = self._index.get(key, 0) % len(workers)
        self._index[key] = idx + 1
        return workers[idx]


class LeastLoadedScheduler(SchedulingStrategy):
    def select_worker(self, job: JobQueueEntry, workers: list[WorkerNode]) -> WorkerNode | None:
        if not workers:
            return None
        return min(workers, key=lambda w: len(w.current_jobs))


class CapabilityMatchingScheduler(SchedulingStrategy):
    def select_worker(self, job: JobQueueEntry, workers: list[WorkerNode]) -> WorkerNode | None:
        if not workers:
            return None
        required = set(job.scanner_ids)
        if not required:
            return min(workers, key=lambda w: len(w.current_jobs))
        matching = [
            w for w in workers
            if w.status == WorkerStatus.ONLINE and any(c.scanner_id in required for c in w.capabilities)
        ]
        if not matching:
            return min(workers, key=lambda w: len(w.current_jobs))
        return min(matching, key=lambda w: len(w.current_jobs))


def create_scheduler(strategy: str) -> SchedulingStrategy:
    strategies: dict[str, Callable[[], SchedulingStrategy]] = {
        "round_robin": lambda: RoundRobinScheduler(),
        "least_loaded": lambda: LeastLoadedScheduler(),
        "capability_matching": lambda: CapabilityMatchingScheduler(),
    }
    factory = strategies.get(strategy)
    if not factory:
        raise ValueError(f"Unknown scheduling strategy: {strategy}")
    return factory()
