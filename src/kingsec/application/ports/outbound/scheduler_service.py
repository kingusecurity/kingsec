"""Port for the scheduled scan engine — no infrastructure imports."""

from __future__ import annotations

from abc import ABC, abstractmethod


class SchedulerServicePort(ABC):
    @abstractmethod
    def calculate_next_run(
        self,
        schedule_type: str,
        cron_expression: str,
        timezone: str,
        after: str | None = None,
    ) -> str | None:
        ...

    @abstractmethod
    def start(self) -> None:
        ...

    @abstractmethod
    def stop(self) -> None:
        ...

    @abstractmethod
    def is_running(self) -> bool:
        ...
