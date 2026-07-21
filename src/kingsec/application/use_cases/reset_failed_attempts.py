from __future__ import annotations

from kingsec.application.ports.outbound.lockout_repository import LockoutRepository
from kingsec.application.use_cases.rate_limit_dto import (
    ResetFailedAttemptsRequest,
    ResetFailedAttemptsResponse,
)


class ResetFailedAttempts:
    def __init__(self, lockout_repo: LockoutRepository) -> None:
        self._lockout_repo = lockout_repo

    def execute(self, request: ResetFailedAttemptsRequest) -> ResetFailedAttemptsResponse:
        self._lockout_repo.delete(request.user_id)
        return ResetFailedAttemptsResponse(success=True)
