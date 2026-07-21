from __future__ import annotations

from kingsec.application.ports.outbound.clock_port import ClockPort
from kingsec.application.ports.outbound.lockout_repository import LockoutRepository
from kingsec.application.use_cases.rate_limit_dto import (
    RecordFailedAuthenticationRequest,
    RecordFailedAuthenticationResponse,
)
from kingsec.domain.rate_limit import AccountLockout


class RecordFailedAuthentication:
    def __init__(
        self,
        lockout_repo: LockoutRepository,
        clock: ClockPort,
        max_attempts: int = 5,
        lockout_duration_seconds: int = 900,
    ) -> None:
        self._lockout_repo = lockout_repo
        self._clock = clock
        self._max_attempts = max_attempts
        self._lockout_duration = lockout_duration_seconds

    def execute(self, request: RecordFailedAuthenticationRequest) -> RecordFailedAuthenticationResponse:
        now = self._clock.now()

        existing = self._lockout_repo.get(request.user_id)
        if existing is not None and now < existing.locked_until:
            return RecordFailedAuthenticationResponse(
                locked=True,
                locked_until=existing.locked_until,
                failed_attempts=existing.failed_attempts,
            )

        attempts = (existing.failed_attempts + 1) if existing else 1

        if attempts >= self._max_attempts:
            locked_until = now + self._lockout_duration
            lockout = AccountLockout(
                user_id=request.user_id,
                locked_until=locked_until,
                failed_attempts=attempts,
            )
            self._lockout_repo.save(lockout)
            return RecordFailedAuthenticationResponse(
                locked=True,
                locked_until=locked_until,
                failed_attempts=attempts,
            )

        lockout = AccountLockout(
            user_id=request.user_id,
            locked_until=0.0,
            failed_attempts=attempts,
        )
        self._lockout_repo.save(lockout)

        return RecordFailedAuthenticationResponse(
            locked=False,
            locked_until=None,
            failed_attempts=attempts,
        )
