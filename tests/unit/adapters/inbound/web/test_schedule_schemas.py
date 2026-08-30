"""Tests for scheduled scan API schemas.

Phase 68 / Finding KSEC-64-04: CreateScheduleBody.schedule_type,
.cron_expression, .timezone, and .retry_strategy previously had no
max_length; UpdateScheduleBody had the same gaps plus a missing
max_length on .description (inconsistent with CreateScheduleBody's own
description field, which already had max_length=1024). The chosen
limits are documented in schedule_schemas.py itself.
"""

from __future__ import annotations

import pytest
from pydantic import ValidationError

from kingsec.adapters.inbound.web.schedule_schemas import CreateScheduleBody, UpdateScheduleBody


def _create(**overrides) -> CreateScheduleBody:
    defaults = dict(name="nightly-scan", target="10.0.0.5")
    defaults.update(overrides)
    return CreateScheduleBody(**defaults)


class TestCreateScheduleBodyScheduleType:
    def test_below_limit_accepted(self) -> None:
        assert len(_create(schedule_type="x" * 31).schedule_type) == 31

    def test_exact_limit_accepted(self) -> None:
        assert len(_create(schedule_type="x" * 32).schedule_type) == 32

    def test_above_limit_rejected(self) -> None:
        with pytest.raises(ValidationError, match="string_too_long"):
            _create(schedule_type="x" * 33)

    def test_real_schedule_types_still_accepted(self) -> None:
        for schedule_type in ("one_time", "hourly", "daily", "weekly", "monthly", "cron"):
            assert _create(schedule_type=schedule_type).schedule_type == schedule_type


class TestCreateScheduleBodyCronExpression:
    def test_below_limit_accepted(self) -> None:
        assert len(_create(cron_expression="x" * 255).cron_expression) == 255

    def test_exact_limit_accepted(self) -> None:
        assert len(_create(cron_expression="x" * 256).cron_expression) == 256

    def test_above_limit_rejected(self) -> None:
        with pytest.raises(ValidationError, match="string_too_long"):
            _create(cron_expression="x" * 257)

    def test_real_cron_expression_still_accepted(self) -> None:
        assert _create(cron_expression="0 2 * * *").cron_expression == "0 2 * * *"


class TestCreateScheduleBodyTimezone:
    def test_below_limit_accepted(self) -> None:
        assert len(_create(timezone="x" * 63).timezone) == 63

    def test_exact_limit_accepted(self) -> None:
        assert len(_create(timezone="x" * 64).timezone) == 64

    def test_above_limit_rejected(self) -> None:
        with pytest.raises(ValidationError, match="string_too_long"):
            _create(timezone="x" * 65)

    def test_real_iana_timezone_still_accepted(self) -> None:
        tz = "America/Argentina/ComodRivadavia"  # one of the longest real IANA names
        assert _create(timezone=tz).timezone == tz


class TestCreateScheduleBodyRetryStrategy:
    def test_below_limit_accepted(self) -> None:
        assert len(_create(retry_strategy="x" * 31).retry_strategy) == 31

    def test_exact_limit_accepted(self) -> None:
        assert len(_create(retry_strategy="x" * 32).retry_strategy) == 32

    def test_above_limit_rejected(self) -> None:
        with pytest.raises(ValidationError, match="string_too_long"):
            _create(retry_strategy="x" * 33)

    def test_real_retry_strategies_still_accepted(self) -> None:
        for retry_strategy in ("no_retry", "fixed"):
            assert _create(retry_strategy=retry_strategy).retry_strategy == retry_strategy


class TestUpdateScheduleBodyDescription:
    """The field CreateScheduleBody already bounded (1024) but
    UpdateScheduleBody had not - the two must agree."""

    def test_below_limit_accepted(self) -> None:
        assert len(UpdateScheduleBody(description="x" * 1023).description) == 1023

    def test_exact_limit_accepted(self) -> None:
        assert len(UpdateScheduleBody(description="x" * 1024).description) == 1024

    def test_above_limit_rejected(self) -> None:
        with pytest.raises(ValidationError, match="string_too_long"):
            UpdateScheduleBody(description="x" * 1025)

    def test_omitted_description_still_accepted(self) -> None:
        assert UpdateScheduleBody().description is None


class TestUpdateScheduleBodyRemainingFields:
    """schedule_type/cron_expression/timezone/retry_strategy mirror
    CreateScheduleBody's bounds exactly - one boundary check per field
    is sufficient given the identical Field() definitions."""

    def test_schedule_type_above_limit_rejected(self) -> None:
        with pytest.raises(ValidationError, match="string_too_long"):
            UpdateScheduleBody(schedule_type="x" * 33)

    def test_cron_expression_above_limit_rejected(self) -> None:
        with pytest.raises(ValidationError, match="string_too_long"):
            UpdateScheduleBody(cron_expression="x" * 257)

    def test_timezone_above_limit_rejected(self) -> None:
        with pytest.raises(ValidationError, match="string_too_long"):
            UpdateScheduleBody(timezone="x" * 65)

    def test_retry_strategy_above_limit_rejected(self) -> None:
        with pytest.raises(ValidationError, match="string_too_long"):
            UpdateScheduleBody(retry_strategy="x" * 33)

    def test_valid_partial_update_still_accepted(self) -> None:
        body = UpdateScheduleBody(name="renamed", description="updated description")
        assert body.name == "renamed"
