"""Calculate the next execution time for a schedule."""

from __future__ import annotations

from kingsec.application.ports.outbound.scheduler_service import SchedulerServicePort


class CalculateNextRun:
    def __init__(self, scheduler_service: SchedulerServicePort) -> None:
        self._scheduler_service = scheduler_service

    def execute(
        self,
        schedule_type: str,
        cron_expression: str,
        timezone: str,
        after: str | None = None,
    ) -> str | None:
        return self._scheduler_service.calculate_next_run(
            schedule_type=schedule_type,
            cron_expression=cron_expression,
            timezone=timezone,
            after=after,
        )
