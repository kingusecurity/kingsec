from __future__ import annotations

import logging
from datetime import UTC, datetime, timedelta

from croniter import croniter

from kingsec.application.ports.outbound import AuditPublisher
from kingsec.domain.audit import AuditAction, AuditEntry
from kingsec.domain.schedule import ScheduleType

logger = logging.getLogger("kingsec.infrastructure.integrations.schedule")


class RecurringAssessmentService:
    def __init__(self, audit: AuditPublisher) -> None:
        self._audit = audit

    def compute_next_run(
        self,
        schedule_type: ScheduleType,
        cron_expression: str,
        timezone: str = "UTC",
        from_dt: datetime | None = None,
    ) -> str | None:
        now = from_dt or datetime.now(UTC)

        if schedule_type == ScheduleType.DAILY:
            next_time = now.replace(hour=2, minute=0, second=0, microsecond=0) + timedelta(days=1)
            if next_time <= now:
                next_time += timedelta(days=1)
            return next_time.isoformat()

        if schedule_type == ScheduleType.WEEKLY:
            days_ahead = (7 - now.weekday()) % 7 or 7
            next_time = (now + timedelta(days=days_ahead)).replace(hour=2, minute=0, second=0, microsecond=0)
            return next_time.isoformat()

        if schedule_type == ScheduleType.MONTHLY:
            next_month = now.month % 12 + 1
            next_year = now.year + (now.month // 12)
            try:
                next_time = now.replace(year=next_year, month=next_month, day=1, hour=2, minute=0, second=0, microsecond=0)
            except Exception:
                return None
            return next_time.isoformat()

        if schedule_type == ScheduleType.CRON and cron_expression:
            try:
                base = from_dt or datetime.now(UTC)
                cron = croniter(cron_expression, base)
                cron_next = cron.get_next(datetime)
                if isinstance(cron_next, datetime):
                    return cron_next.isoformat()
            except (ValueError, KeyError):
                logger.warning("Invalid cron expression: %s", cron_expression)
                return None

        return None

    def get_missed_runs(
        self,
        schedule_type: ScheduleType,
        cron_expression: str,
        last_run: str | None,
        now: str | None = None,
    ) -> list[str]:
        now_dt = datetime.fromisoformat(now) if now else datetime.now(UTC)
        if last_run is None:
            return [now_dt.isoformat()]

        last_dt = datetime.fromisoformat(last_run)
        missed: list[str] = []

        if schedule_type == ScheduleType.DAILY:
            cursor = last_dt + timedelta(days=1)
            while cursor + timedelta(days=1) <= now_dt:
                missed.append(cursor.isoformat())
                cursor += timedelta(days=1)

        elif schedule_type == ScheduleType.WEEKLY:
            cursor = last_dt + timedelta(weeks=1)
            while cursor + timedelta(weeks=1) <= now_dt:
                missed.append(cursor.isoformat())
                cursor += timedelta(weeks=1)

        elif schedule_type == ScheduleType.MONTHLY:
            cursor = last_dt + timedelta(days=28)
            while cursor + timedelta(days=28) <= now_dt:
                missed.append(cursor.isoformat())
                cursor += timedelta(days=28)

        elif schedule_type == ScheduleType.CRON and cron_expression:
            try:
                cron = croniter(cron_expression, last_dt)
                while True:
                    next_time = cron.get_next(datetime)
                    if next_time > now_dt:
                        break
                    missed.append(next_time.isoformat())
            except (ValueError, KeyError):
                pass

        if missed:
            self._audit.record(AuditEntry(
                action=AuditAction.HEALTH_CHECK,
                resource_type="schedule_missed",
                success=True,
                reason=f"{len(missed)} missed run(s) detected",
                metadata={
                    "schedule_type": schedule_type.value,
                    "missed_count": len(missed),
                    "last_run": last_run,
                },
            ))

        return missed
