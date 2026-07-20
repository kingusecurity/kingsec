from __future__ import annotations

import threading

from kingsec.application.ports.outbound.lockout_repository import LockoutRepository
from kingsec.domain.rate_limit import AccountLockout


class InMemoryLockoutRepository(LockoutRepository):
    def __init__(self) -> None:
        self._lockouts: dict[str, AccountLockout] = {}
        self._lock = threading.Lock()

    def get(self, user_id: str) -> AccountLockout | None:
        with self._lock:
            return self._lockouts.get(user_id)

    def save(self, lockout: AccountLockout) -> None:
        with self._lock:
            self._lockouts[lockout.user_id] = lockout

    def delete(self, user_id: str) -> None:
        with self._lock:
            self._lockouts.pop(user_id, None)
