from __future__ import annotations

from abc import ABC, abstractmethod

from kingsec.domain.session import Session


class SessionRepository(ABC):
    @abstractmethod
    def save(self, session: Session) -> None: ...

    @abstractmethod
    def find_by_id(self, session_id: str) -> Session | None: ...

    @abstractmethod
    def find_by_jti(self, jti: str) -> Session | None: ...

    @abstractmethod
    def find_by_refresh_jti(self, refresh_jti: str) -> Session | None: ...

    @abstractmethod
    def find_active_by_user(self, user_id: str) -> list[Session]: ...

    @abstractmethod
    def count_active_by_user(self, user_id: str) -> int: ...

    @abstractmethod
    def revoke(self, session_id: str) -> None: ...

    @abstractmethod
    def revoke_all_by_user(self, user_id: str, exclude_session_id: str | None = None) -> None: ...

    @abstractmethod
    def update_activity(self, session_id: str, last_activity: str) -> None: ...

    @abstractmethod
    def update_refresh_jti(self, session_id: str, new_refresh_jti: str) -> None: ...

    @abstractmethod
    def update_access_jti(self, session_id: str, new_access_jti: str) -> None: ...

    @abstractmethod
    def delete_expired(self, before: str) -> int: ...
