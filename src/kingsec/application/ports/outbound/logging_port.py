from __future__ import annotations

from abc import ABC, abstractmethod
from typing import Any


class LoggingPort(ABC):
    @abstractmethod
    def info(self, message: str, **context: Any) -> None:
        ...

    @abstractmethod
    def warn(self, message: str, **context: Any) -> None:
        ...

    @abstractmethod
    def error(self, message: str, **context: Any) -> None:
        ...

    @abstractmethod
    def debug(self, message: str, **context: Any) -> None:
        ...
