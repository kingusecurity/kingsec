from __future__ import annotations

from kingsec.application.ports.outbound.lockout_repository import LockoutRepository
from kingsec.application.use_cases.rate_limit_dto import (
    RecordSuccessfulAuthenticationRequest,
    RecordSuccessfulAuthenticationResponse,
)


class RecordSuccessfulAuthentication:
    def __init__(self, lockout_repo: LockoutRepository) -> None:
        self._lockout_repo = lockout_repo

    def execute(self, request: RecordSuccessfulAuthenticationRequest) -> RecordSuccessfulAuthenticationResponse:
        existing = self._lockout_repo.get(request.user_id)
        previous = existing.failed_attempts if existing else 0

        self._lockout_repo.delete(request.user_id)

        return RecordSuccessfulAuthenticationResponse(
            previous_failed_attempts=previous,
        )
