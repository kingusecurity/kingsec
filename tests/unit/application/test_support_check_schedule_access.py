"""Dedicated unit tests for check_schedule_access (KSEC-69-01 fix).

Phase 70 / Section 10: proves the ownership-check helper in isolation,
independent of any use case that calls it.
"""

from __future__ import annotations

import pytest

from kingsec.application._support import check_schedule_access
from kingsec.application.errors import ScheduleNotFoundError
from kingsec.domain.schedule import RetryPolicy, ScanSchedule, ScheduleId, ScheduleStatus, ScheduleType


def _make_schedule(owner_user_id: str) -> ScanSchedule:
    return ScanSchedule(
        id=ScheduleId("sched-1"),
        name="Test Schedule",
        description="",
        owner_user_id=owner_user_id,
        target="10.0.0.1",
        scanner_ids=(),
        config={},
        schedule_type=ScheduleType.ONE_TIME,
        cron_expression="",
        timezone="UTC",
        enabled=True,
        paused=False,
        created_at="2026-01-01T00:00:00",
        updated_at="2026-01-01T00:00:00",
        retry_policy=RetryPolicy(),
        current_retry_count=0,
        status=ScheduleStatus.ACTIVE,
    )


class TestCheckScheduleAccess:
    def test_admin_is_allowed_regardless_of_ownership(self) -> None:
        schedule = _make_schedule(owner_user_id="alice")
        check_schedule_access(schedule, requesting_user="admin1", is_admin=True)

    def test_owner_is_allowed(self) -> None:
        schedule = _make_schedule(owner_user_id="alice")
        check_schedule_access(schedule, requesting_user="alice", is_admin=False)

    def test_non_owner_non_admin_raises_not_found(self) -> None:
        schedule = _make_schedule(owner_user_id="alice")
        with pytest.raises(ScheduleNotFoundError):
            check_schedule_access(schedule, requesting_user="mallory", is_admin=False)

    def test_missing_owner_fails_closed_for_non_admin(self) -> None:
        """A schedule with no recorded owner is Admin-only, not open to everyone."""
        schedule = _make_schedule(owner_user_id="")
        with pytest.raises(ScheduleNotFoundError):
            check_schedule_access(schedule, requesting_user="anyone", is_admin=False)

    def test_missing_owner_still_allowed_for_admin(self) -> None:
        schedule = _make_schedule(owner_user_id="")
        check_schedule_access(schedule, requesting_user="admin1", is_admin=True)

    def test_empty_requesting_user_never_matches_a_real_owner(self) -> None:
        schedule = _make_schedule(owner_user_id="alice")
        with pytest.raises(ScheduleNotFoundError):
            check_schedule_access(schedule, requesting_user="", is_admin=False)
