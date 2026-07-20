"""List scheduled scans (own or all for admin)."""

from __future__ import annotations

from kingsec.application.ports.outbound.schedule_repository import ScheduleRepositoryPort

from .create_schedule import _to_view
from .schedule_dto import ListSchedulesRequest, ListSchedulesResponse


class ListSchedules:
    def __init__(self, repository: ScheduleRepositoryPort) -> None:
        self._repository = repository

    def execute(self, request: ListSchedulesRequest) -> ListSchedulesResponse:
        if request.is_admin:
            schedules = self._repository.find_all()
        else:
            schedules = self._repository.find_by_user_id(request.requesting_user_id)

        return ListSchedulesResponse(
            schedules=[_to_view(s) for s in schedules],
        )
