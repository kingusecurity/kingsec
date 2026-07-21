"""Cron expression parser — encapsulated behind SchedulerServicePort.

This is a minimal implementation supporting standard cron expressions
with 5 fields: minute hour day-of-month month day-of-week.
"""

from __future__ import annotations

from datetime import datetime, timedelta
from typing import ClassVar


class CronParser:
    """Minimal cron expression parser (5-field: minute hour dom month dow)."""

    _ALL: ClassVar[list[range]] = [
        range(0, 60),  # minute
        range(0, 24),  # hour
        range(1, 32),  # day of month
        range(1, 13),  # month
        range(0, 7),  # day of week (0=Sunday)
    ]

    @classmethod
    def get_next(cls, expression: str, after: datetime) -> datetime | None:
        """Calculate the next datetime matching the cron expression after *after*."""
        fields = expression.strip().split()
        if len(fields) != 5:
            return None

        parsed: list[set[int]] = []
        for i, field in enumerate(fields):
            try:
                parsed.append(cls._parse_field(field, cls._ALL[i]))
            except (ValueError, IndexError):
                return None

        minute_set, hour_set, dom_set, month_set, dow_set = parsed
        base = after.replace(tzinfo=None)
        candidate = base.replace(second=0, microsecond=0) + timedelta(minutes=1)

        for _ in range(525600):  # max 1 year ahead
            if candidate.month not in month_set:
                candidate = (candidate.replace(day=1) + timedelta(days=32)).replace(day=1)
                continue
            dom_matches = candidate.day in dom_set
            dow_matches = (candidate.weekday() + 1) % 7 in dow_set
            if not dom_matches and not dow_matches:
                candidate += timedelta(days=1)
                continue
            if candidate.hour not in hour_set:
                candidate += timedelta(hours=1)
                candidate = candidate.replace(minute=0)
                continue
            if candidate.minute not in minute_set:
                candidate += timedelta(minutes=1)
                continue
            return candidate

        return None

    @staticmethod
    def _parse_field(field: str, allowed: range) -> set[int]:
        if field == "*":
            return set(allowed)
        if "/" in field:
            parts = field.split("/")
            base = CronParser._parse_field(parts[0], allowed)
            step = int(parts[1])
            return {v for v in base if (v - min(base)) % step == 0}
        if "," in field:
            return {int(x) for x in field.split(",") if int(x) in allowed}
        if "-" in field:
            start, end = (int(x) for x in field.split("-"))
            return {v for v in allowed if start <= v <= end}
        v = int(field)
        if v in allowed:
            return {v}
        raise ValueError(f"value {v} out of range {allowed}")
