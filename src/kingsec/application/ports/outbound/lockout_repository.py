from __future__ import annotations

from abc import ABC, abstractmethod

from kingsec.domain.rate_limit import AccountLockout


class LockoutRepository(ABC):
    @abstractmethod
    def get(self, user_id: str) -> AccountLockout | None: ...

    @abstractmethod
    def save(self, lockout: AccountLockout) -> None: ...

    @abstractmethod
    def delete(self, user_id: str) -> None: ...
