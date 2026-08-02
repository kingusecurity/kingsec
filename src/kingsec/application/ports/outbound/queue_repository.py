from __future__ import annotations

from abc import ABC, abstractmethod

from kingsec.domain.queue import QueueEntry, QueueStatistics


class QueueRepositoryPort(ABC):
    @abstractmethod
    def enqueue(self, entry: QueueEntry) -> None: ...

    @abstractmethod
    def dequeue(self, entry_id: str) -> QueueEntry | None: ...

    @abstractmethod
    def peek(self, entry_id: str) -> QueueEntry | None: ...

    @abstractmethod
    def remove(self, entry_id: str) -> None: ...

    @abstractmethod
    def find_ready(self) -> list[QueueEntry]: ...

    @abstractmethod
    def find_waiting(self) -> list[QueueEntry]: ...

    @abstractmethod
    def find_running(self) -> list[QueueEntry]: ...

    @abstractmethod
    def find_all(self) -> list[QueueEntry]: ...

    @abstractmethod
    def update(self, entry: QueueEntry) -> None: ...

    @abstractmethod
    def statistics(self) -> QueueStatistics: ...

    @abstractmethod
    def pause(self) -> None: ...

    @abstractmethod
    def resume(self) -> None: ...
