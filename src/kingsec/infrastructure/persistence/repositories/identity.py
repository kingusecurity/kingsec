"""SQLAlchemy-backed IdentityProviderRepositoryPort and SSOSessionRepositoryPort."""

from __future__ import annotations

from datetime import UTC, datetime

from sqlalchemy import delete, select
from sqlalchemy.orm import Session

from kingsec.application.idp.ports import (
    AccountLinkRepositoryPort,
    IdentityProviderRepositoryPort,
    SSOSessionRepositoryPort,
)
from kingsec.domain.identity import AccountLink, IdentityProvider, SSOSession
from kingsec.infrastructure.persistence.mappers import (
    account_link_to_domain,
    account_link_to_orm,
    identity_provider_to_domain,
    identity_provider_to_orm,
    sso_session_to_domain,
    sso_session_to_orm,
)
from kingsec.infrastructure.persistence.models import AccountLinkModel, IdentityProviderModel, SSOSessionModel


class SQLAlchemyIdentityProviderRepository(IdentityProviderRepositoryPort):
    def __init__(self, session: Session) -> None:
        self._session = session

    def save(self, provider: IdentityProvider) -> IdentityProvider:
        orm = identity_provider_to_orm(provider)
        self._session.merge(orm)
        self._session.commit()
        return provider

    def get(self, provider_id: str) -> IdentityProvider | None:
        stmt = select(IdentityProviderModel).where(IdentityProviderModel.id == provider_id)
        orm = self._session.execute(stmt).scalar_one_or_none()
        return identity_provider_to_domain(orm) if orm else None

    def find_all(self) -> list[IdentityProvider]:
        stmt = select(IdentityProviderModel).order_by(IdentityProviderModel.created_at.desc())
        rows = self._session.execute(stmt).scalars().all()
        return [identity_provider_to_domain(r) for r in rows]

    def find_by_protocol(self, protocol: str) -> list[IdentityProvider]:
        stmt = select(IdentityProviderModel).where(IdentityProviderModel.protocol == protocol)
        rows = self._session.execute(stmt).scalars().all()
        return [identity_provider_to_domain(r) for r in rows]

    def find_by_domain(self, domain: str) -> list[IdentityProvider]:
        stmt = select(IdentityProviderModel).where(IdentityProviderModel.domain_hint == domain)
        rows = self._session.execute(stmt).scalars().all()
        return [identity_provider_to_domain(r) for r in rows]

    def find_active(self) -> list[IdentityProvider]:
        stmt = select(IdentityProviderModel).where(IdentityProviderModel.status == "active")
        rows = self._session.execute(stmt).scalars().all()
        return [identity_provider_to_domain(r) for r in rows]

    def delete(self, provider_id: str) -> None:
        stmt = delete(IdentityProviderModel).where(IdentityProviderModel.id == provider_id)
        self._session.execute(stmt)
        self._session.commit()


class SQLAlchemySSOSessionRepository(SSOSessionRepositoryPort):
    def __init__(self, session: Session) -> None:
        self._session = session

    def save(self, session: SSOSession) -> SSOSession:
        orm = sso_session_to_orm(session)
        self._session.add(orm)
        self._session.commit()
        return session

    def get(self, session_id: str) -> SSOSession | None:
        stmt = select(SSOSessionModel).where(SSOSessionModel.id == session_id)
        orm = self._session.execute(stmt).scalar_one_or_none()
        return sso_session_to_domain(orm) if orm else None

    def find_by_user(self, user_id: str) -> list[SSOSession]:
        stmt = select(SSOSessionModel).where(SSOSessionModel.user_id == user_id)
        rows = self._session.execute(stmt).scalars().all()
        return [sso_session_to_domain(r) for r in rows]

    def find_by_provider(self, provider_id: str) -> list[SSOSession]:
        stmt = select(SSOSessionModel).where(SSOSessionModel.provider_id == provider_id)
        rows = self._session.execute(stmt).scalars().all()
        return [sso_session_to_domain(r) for r in rows]

    def find_active_by_user(self, user_id: str) -> list[SSOSession]:
        stmt = select(SSOSessionModel).where(
            SSOSessionModel.user_id == user_id,
            SSOSessionModel.is_active.is_(True),
        )
        rows = self._session.execute(stmt).scalars().all()
        return [sso_session_to_domain(r) for r in rows]

    def update(self, session: SSOSession) -> None:
        orm = sso_session_to_orm(session)
        self._session.merge(orm)
        self._session.commit()

    def delete(self, session_id: str) -> None:
        stmt = delete(SSOSessionModel).where(SSOSessionModel.id == session_id)
        self._session.execute(stmt)
        self._session.commit()

    def delete_expired(self) -> int:
        now = datetime.now(UTC).isoformat()
        stmt = delete(SSOSessionModel).where(
            SSOSessionModel.expires_at < now,
            SSOSessionModel.expires_at != "",
        )
        self._session.execute(stmt)
        self._session.commit()
        return 0


class SQLAlchemyAccountLinkRepository(AccountLinkRepositoryPort):
    def __init__(self, session: Session) -> None:
        self._session = session

    def save(self, link: AccountLink) -> AccountLink:
        orm = account_link_to_orm(link)
        self._session.merge(orm)
        self._session.commit()
        return link

    def find_by_user(self, user_id: str) -> list[AccountLink]:
        stmt = select(AccountLinkModel).where(AccountLinkModel.user_id == user_id)
        rows = self._session.execute(stmt).scalars().all()
        return [account_link_to_domain(r) for r in rows]

    def find_by_provider_and_external_id(self, provider_id: str, external_user_id: str) -> AccountLink | None:
        stmt = select(AccountLinkModel).where(
            AccountLinkModel.provider_id == provider_id,
            AccountLinkModel.external_user_id == external_user_id,
        )
        orm = self._session.execute(stmt).scalar_one_or_none()
        return account_link_to_domain(orm) if orm else None

    def find_by_provider(self, provider_id: str) -> list[AccountLink]:
        stmt = select(AccountLinkModel).where(AccountLinkModel.provider_id == provider_id)
        rows = self._session.execute(stmt).scalars().all()
        return [account_link_to_domain(r) for r in rows]

    def delete(self, link_id: str) -> None:
        stmt = delete(AccountLinkModel).where(AccountLinkModel.id == link_id)
        self._session.execute(stmt)
        self._session.commit()
