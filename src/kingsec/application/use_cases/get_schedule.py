"""Get a single scheduled scan by ID."""

from __future__ import annotations

from kingsec.application._support import check_schedule_access
from kingsec.application.ports.outbound.schedule_repository import ScheduleRepositoryPort

from .create_schedule import _to_view
from .schedule_dto import GetScheduleRequest, GetScheduleResponse


class GetSchedule:
    def __init__(self, repository: ScheduleRepositoryPort) -> None:
        self._repository = repository

    def execute(self, request: GetScheduleRequest) -> GetScheduleResponse:
        schedule = self._repository.find_by_id(request.schedule_id)
        if schedule is None:
            from kingsec.application.errors import ScheduleNotFoundError

            raise ScheduleNotFoundError(f"schedule '{request.schedule_id}' not found")

        # KSEC-69-01: raises the identical ScheduleNotFoundError a
        # missing schedule already raises above, so a non-owner cannot
        # tell "doesn't exist" from "exists but isn't yours".
        check_schedule_access(schedule, request.requesting_user_id, request.is_admin)

        return GetScheduleResponse(schedule=_to_view(schedule))
