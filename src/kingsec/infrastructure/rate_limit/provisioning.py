from __future__ import annotations

from kingsec.application.ports.outbound.clock_port import ClockPort
from kingsec.application.ports.outbound.lockout_repository import LockoutRepository
from kingsec.application.ports.outbound.rate_limiter import RateLimiterPort
from kingsec.infrastructure._container import ContainerProtocol
from kingsec.infrastructure.config.settings import Settings

from .in_memory_lockout_repository import InMemoryLockoutRepository
from .in_memory_rate_limiter import InMemoryRateLimiter
from .system_clock import SystemClock


def register_rate_limiter(container: ContainerProtocol, settings: Settings) -> None:
    rate_limiter = InMemoryRateLimiter()
    clock: ClockPort = SystemClock()
    lockout_repo: LockoutRepository = InMemoryLockoutRepository()

    container.register_instance(RateLimiterPort, rate_limiter)
    container.register_instance(ClockPort, clock)
    container.register_instance(LockoutRepository, lockout_repo)
