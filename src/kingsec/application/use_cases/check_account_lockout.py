from __future__ import annotations

from kingsec.application.ports.outbound.clock_port import ClockPort
from kingsec.application.ports.outbound.lockout_repository import LockoutRepository
from kingsec.application.use_cases.rate_limit_dto import (
    CheckAccountLockoutRequest,
    CheckAccountLockoutResponse,
)


class CheckAccountLockout:
    def __init__(self, lockout_repo: LockoutRepository, clock: ClockPort) -> None:
        self._lockout_repo = lockout_repo
        self._clock = clock

    def execute(self, request: CheckAccountLockoutRequest) -> CheckAccountLockoutResponse:
        now = self._clock.now()
        existing = self._lockout_repo.get(request.user_id)

        if existing is None:
            return CheckAccountLockoutResponse(
                locked=False,
                locked_until=None,
                failed_attempts=0,
            )

        if existing.locked_until <= 0:
            # RecordFailedAuthentication saves a record with locked_until=0.0
            # to track an attempt count that hasn't crossed the lockout
            # threshold yet - it isn't a lock, so there's nothing to clear
            # and `now >= 0` must not be treated as "this lock expired"
            # (it always is, which would silently wipe the in-progress
            # attempt count on every check before it ever reaches the
            # threshold).
            return CheckAccountLockoutResponse(
                locked=False,
                locked_until=None,
                failed_attempts=existing.failed_attempts,
            )

        if now >= existing.locked_until:
            self._lockout_repo.delete(request.user_id)
            return CheckAccountLockoutResponse(
                locked=False,
                locked_until=None,
                failed_attempts=0,
            )

        return CheckAccountLockoutResponse(
            locked=True,
            locked_until=existing.locked_until,
            failed_attempts=existing.failed_attempts,
        )
