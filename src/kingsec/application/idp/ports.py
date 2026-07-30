"""Repository ports for identity provider infrastructure."""

from __future__ import annotations

from abc import ABC, abstractmethod

from kingsec.domain.identity import AccountLink, IdentityProvider, SSOSession


class IdentityProviderRepositoryPort(ABC):
    @abstractmethod
    def save(self, provider: IdentityProvider) -> IdentityProvider: ...

    @abstractmethod
    def get(self, provider_id: str) -> IdentityProvider | None: ...

    @abstractmethod
    def find_all(self) -> list[IdentityProvider]: ...

    @abstractmethod
    def find_by_protocol(self, protocol: str) -> list[IdentityProvider]: ...

    @abstractmethod
    def find_by_domain(self, domain: str) -> list[IdentityProvider]: ...

    @abstractmethod
    def find_active(self) -> list[IdentityProvider]: ...

    @abstractmethod
    def delete(self, provider_id: str) -> None: ...


class SSOSessionRepositoryPort(ABC):
    @abstractmethod
    def save(self, session: SSOSession) -> SSOSession: ...

    @abstractmethod
    def get(self, session_id: str) -> SSOSession | None: ...

    @abstractmethod
    def find_by_user(self, user_id: str) -> list[SSOSession]: ...

    @abstractmethod
    def find_by_provider(self, provider_id: str) -> list[SSOSession]: ...

    @abstractmethod
    def find_active_by_user(self, user_id: str) -> list[SSOSession]: ...

    @abstractmethod
    def update(self, session: SSOSession) -> None: ...

    @abstractmethod
    def delete(self, session_id: str) -> None: ...

    @abstractmethod
    def delete_expired(self) -> int: ...


class AccountLinkRepositoryPort(ABC):
    @abstractmethod
    def save(self, link: AccountLink) -> AccountLink: ...

    @abstractmethod
    def find_by_user(self, user_id: str) -> list[AccountLink]: ...

    @abstractmethod
    def find_by_provider_and_external_id(self, provider_id: str, external_user_id: str) -> AccountLink | None: ...

    @abstractmethod
    def find_by_provider(self, provider_id: str) -> list[AccountLink]: ...

    @abstractmethod
    def delete(self, link_id: str) -> None: ...
