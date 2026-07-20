from __future__ import annotations

from abc import ABC, abstractmethod

from kingsec.domain.agent import Agent
from kingsec.domain.queue import QueueEntry, QueuePriority


class SchedulerPolicyPort(ABC):
    @abstractmethod
    def select_next_job(self, ready_entries: list[QueueEntry]) -> QueueEntry | None:
        ...

    @abstractmethod
    def allocate_agent(self, entry: QueueEntry, available_agents: list[Agent]) -> Agent | None:
        ...

    @abstractmethod
    def calculate_priority(self, entry: QueueEntry) -> QueuePriority:
        ...
