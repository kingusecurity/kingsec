from __future__ import annotations

from abc import ABC, abstractmethod


class ClockPort(ABC):
    @abstractmethod
    def now(self) -> float: ...
