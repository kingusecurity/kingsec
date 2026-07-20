from __future__ import annotations

from abc import ABC, abstractmethod


class LifecycleManagerPort(ABC):
    @abstractmethod
    def shutdown(self) -> None:
        ...

    @abstractmethod
    def restart(self) -> None:
        ...

    @abstractmethod
    def is_running(self) -> bool:
        ...

    @abstractmethod
    def uptime_seconds(self) -> float:
        ...

    @abstractmethod
    def get_service_status(self) -> str:
        ...
