from __future__ import annotations

from abc import ABC, abstractmethod

from kingsec.domain.rate_limit import RateLimitDecision, RateLimitPolicy


class RateLimiterPort(ABC):
    @abstractmethod
    def check(self, key: str, policy: RateLimitPolicy) -> RateLimitDecision: ...

    @abstractmethod
    def record(self, key: str, policy: RateLimitPolicy) -> None: ...

    @abstractmethod
    def reset(self, key: str) -> None: ...
