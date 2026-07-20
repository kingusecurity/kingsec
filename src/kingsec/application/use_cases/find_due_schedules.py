"""Find all schedules that are due for execution."""

from __future__ import annotations

from datetime import UTC, datetime

from kingsec.application.ports.outbound.schedule_repository import ScheduleRepositoryPort

from .create_schedule import _to_view
from .schedule_dto import ListSchedulesResponse


class FindDueSchedules:
    def __init__(self, repository: ScheduleRepositoryPort) -> None:
        self._repository = repository

    def execute(self) -> ListSchedulesResponse:
        now = datetime.now(UTC).isoformat()
        due = self._repository.find_due(now)
        return ListSchedulesResponse(
            schedules=[_to_view(s) for s in due],
        )
