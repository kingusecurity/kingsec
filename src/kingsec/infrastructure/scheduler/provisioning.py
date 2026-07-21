"""DI wiring for scheduler infrastructure."""

from __future__ import annotations

from typing import TYPE_CHECKING, Any

from kingsec.application.ports.outbound.schedule_repository import ScheduleRepositoryPort
from kingsec.application.ports.outbound.scheduler_service import SchedulerServicePort

from .in_process_scheduler import InProcessScheduler
from .sqlalchemy_schedule_repository import SqlAlchemyScheduleRepository

if TYPE_CHECKING:
    from sqlalchemy.orm import Session, sessionmaker


def register_scheduler(container: Any, session_factory: sessionmaker[Session]) -> None:
    """Register scheduler infrastructure on the DI container."""
    repository = SqlAlchemyScheduleRepository(session_factory)
    container.register_instance(ScheduleRepositoryPort, repository)

    def _create_scheduler(c: Any) -> SchedulerServicePort:
        from kingsec.application.ports.job_service import JobServicePort
        from kingsec.application.ports.outbound.clock_port import ClockPort

        scheduler = InProcessScheduler(
            repository=c.resolve(ScheduleRepositoryPort),
            job_service=c.resolve(JobServicePort),
            clock=c.resolve(ClockPort),
        )
        container.add_shutdown_hook(scheduler.stop)
        return scheduler

    container.register_factory(SchedulerServicePort, _create_scheduler)
