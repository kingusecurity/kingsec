from __future__ import annotations

from abc import ABC, abstractmethod

from kingsec.domain.queue import QueueEntry, QueueStatistics


class QueueServicePort(ABC):
    @abstractmethod
    def enqueue(
        self,
        payload: str,
        target: str,
        priority: str = "normal",
        scanner_ids: list[str] | None = None,
        owner_user_id: str = "",
        estimated_duration_seconds: int = 300,
    ) -> QueueEntry: ...

    @abstractmethod
    def dequeue(self, entry_id: str) -> QueueEntry: ...

    @abstractmethod
    def peek(self, entry_id: str) -> QueueEntry: ...

    @abstractmethod
    def cancel(self, entry_id: str) -> None: ...

    @abstractmethod
    def pause(self) -> None: ...

    @abstractmethod
    def resume(self) -> None: ...

    @abstractmethod
    def list_queue(self) -> list[QueueEntry]: ...

    @abstractmethod
    def get_statistics(self) -> QueueStatistics: ...

    @abstractmethod
    def change_priority(self, entry_id: str, priority: str) -> QueueEntry: ...

    @abstractmethod
    def move_position(self, entry_id: str, new_position: int) -> QueueEntry: ...

    @abstractmethod
    def assign_best_agent(self, entry_id: str) -> str | None: ...

    @abstractmethod
    def get_next(self) -> QueueEntry | None: ...
