"""Tests for the cron expression parser."""

from __future__ import annotations

from datetime import datetime

from kingsec.infrastructure.scheduler.cron_parser import CronParser


class TestCronParser:
    def test_every_minute(self) -> None:
        after = datetime(2025, 1, 1, 10, 0)
        result = CronParser.get_next("* * * * *", after)
        assert result is not None
        assert result > after

    def test_hourly_at_minute_0(self) -> None:
        after = datetime(2025, 1, 1, 10, 30)
        result = CronParser.get_next("0 * * * *", after)
        assert result is not None
        assert result == datetime(2025, 1, 1, 11, 0)

    def test_daily_at_2am(self) -> None:
        after = datetime(2025, 1, 1, 10, 0)
        result = CronParser.get_next("0 2 * * *", after)
        assert result is not None
        assert result == datetime(2025, 1, 2, 2, 0)

    def test_every_15_minutes(self) -> None:
        after = datetime(2025, 1, 1, 10, 0)
        result = CronParser.get_next("*/15 * * * *", after)
        assert result is not None
        assert result == datetime(2025, 1, 1, 10, 15)

    def test_specific_time(self) -> None:
        after = datetime(2025, 1, 1, 9, 0)
        result = CronParser.get_next("30 9 * * *", after)
        assert result is not None
        assert result == datetime(2025, 1, 1, 9, 30)

    def test_invalid_expression(self) -> None:
        result = CronParser.get_next("invalid", datetime(2025, 1, 1))
        assert result is None

    def test_wrong_field_count(self) -> None:
        result = CronParser.get_next("* * * * * *", datetime(2025, 1, 1))
        assert result is None
