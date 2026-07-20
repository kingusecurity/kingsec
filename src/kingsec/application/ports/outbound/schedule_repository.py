"""Port for schedule persistence — no infrastructure imports."""

from __future__ import annotations

from abc import ABC, abstractmethod

from kingsec.domain.schedule import ScanSchedule


class ScheduleRepositoryPort(ABC):
    @abstractmethod
    def save(self, schedule: ScanSchedule) -> None:
        ...

    @abstractmethod
    def find_by_id(self, schedule_id: str) -> ScanSchedule | None:
        ...

    @abstractmethod
    def find_by_user_id(self, user_id: str) -> list[ScanSchedule]:
        ...

    @abstractmethod
    def find_all(self) -> list[ScanSchedule]:
        ...

    @abstractmethod
    def find_due(self, now_utc_str: str) -> list[ScanSchedule]:
        ...

    @abstractmethod
    def delete(self, schedule_id: str) -> None:
        ...
