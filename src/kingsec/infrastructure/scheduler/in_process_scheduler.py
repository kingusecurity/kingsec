"""In-process background scheduler — polls for due schedules and submits jobs.

Single-process, no threading redesign, no Celery, no Redis.
"""

from __future__ import annotations

import threading
from datetime import UTC, datetime, timedelta
from typing import TYPE_CHECKING

from kingsec.application.ports.outbound.scheduler_service import SchedulerServicePort
from kingsec.domain.schedule import ScheduleType
from kingsec.infrastructure.logging import get_logger

from .cron_parser import CronParser

_logger = get_logger("kingsec.infrastructure.scheduler.in_process_scheduler")

if TYPE_CHECKING:
    from kingsec.application.ports.job_service import JobServicePort
    from kingsec.application.ports.outbound.clock_port import ClockPort
    from kingsec.application.ports.outbound.schedule_repository import ScheduleRepositoryPort


class InProcessScheduler(SchedulerServicePort):
    """Single-process scheduler that polls for due schedules in a background thread.

    Never executes scanners directly — only submits jobs through JobServicePort.
    """

    _POLL_INTERVAL_SECONDS: int = 60

    def __init__(
        self,
        repository: ScheduleRepositoryPort,
        job_service: JobServicePort,
        clock: ClockPort,
    ) -> None:
        self._repository = repository
        self._job_service = job_service
        self._clock = clock
        self._running = False
        self._thread: threading.Thread | None = None
        self._stop_event = threading.Event()

    def start(self) -> None:
        if self._running:
            return
        self._running = True
        self._stop_event.clear()
        self._thread = threading.Thread(target=self._run_loop, daemon=True)
        self._thread.start()

    def stop(self) -> None:
        self._running = False
        self._stop_event.set()
        if self._thread is not None:
            self._thread.join(timeout=5)
            self._thread = None

    def is_running(self) -> bool:
        return self._running

    def calculate_next_run(
        self,
        schedule_type: str,
        cron_expression: str,
        timezone: str,
        after: str | None = None,
    ) -> str | None:
        """Calculate next run time based on schedule type and timezone."""
        from zoneinfo import ZoneInfo

        try:
            tz = ZoneInfo(timezone)
        except Exception:
            # Fall back to UTC for unknown/invalid timezone strings.
            tz = UTC

        base = datetime.fromisoformat(after) if after else datetime.now(UTC)
        base_utc = base.astimezone(UTC).replace(tzinfo=None)

        try:
            stype = ScheduleType(schedule_type)
        except ValueError:
            stype = ScheduleType.ONE_TIME

        if stype == ScheduleType.ONE_TIME:
            return None

        if stype == ScheduleType.HOURLY:
            return (base_utc + timedelta(hours=1)).isoformat()

        if stype == ScheduleType.DAILY:
            return (base_utc + timedelta(days=1)).isoformat()

        if stype == ScheduleType.WEEKLY:
            return (base_utc + timedelta(weeks=1)).isoformat()

        if stype == ScheduleType.MONTHLY:
            return (base_utc + timedelta(days=30)).isoformat()

        if stype == ScheduleType.CRON and cron_expression:
            parsed = CronParser.get_next(cron_expression, base_utc)
            if parsed:
                return parsed.replace(tzinfo=None).isoformat()

        return None

    def _run_loop(self) -> None:
        while not self._stop_event.is_set():
            try:
                self._poll_due_schedules()
            except Exception:
                _logger.exception("scheduler poll cycle failed")
            self._stop_event.wait(self._POLL_INTERVAL_SECONDS)

    def _poll_due_schedules(self) -> None:
        now_utc = datetime.now(UTC).isoformat()
        due = self._repository.find_due(now_utc)

        for schedule in due:
            try:
                job = self._job_service.submit_scan(
                    target=schedule.target,
                    config={
                        "schedule_id": str(schedule.id),
                        "scanner_ids": list(schedule.scanner_ids),
                        **schedule.config,
                    },
                )

                next_run = self.calculate_next_run(
                    schedule_type=schedule.schedule_type.value,
                    cron_expression=schedule.cron_expression,
                    timezone=schedule.timezone,
                    after=now_utc,
                )

                updated = schedule.with_run_completed(next_run=next_run, now=now_utc)
                self._repository.save(updated)
            except Exception:
                _logger.exception(
                    "failed to process due schedule",
                    schedule_id=str(schedule.id),
                )
