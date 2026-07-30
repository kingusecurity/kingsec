"""Just-In-Time (JIT) user provisioning for SSO identity providers."""

from __future__ import annotations

from uuid import uuid4

from kingsec.application.idp.ports import AccountLinkRepositoryPort
from kingsec.application.idp.role_mapping_service import RoleMappingService
from kingsec.application.ports.outbound import UserRepository
from kingsec.domain.identity import AccountLink, IdentityProvider
from kingsec.domain.user import User


class JITProvisioningService:
    def __init__(
        self,
        user_repo: UserRepository,
        account_link_repo: AccountLinkRepositoryPort,
        role_mapping: RoleMappingService,
    ) -> None:
        self._user_repo = user_repo
        self._account_link_repo = account_link_repo
        self._role_mapping = role_mapping

    def provision(
        self,
        provider: IdentityProvider,
        external_user_id: str,
        email: str,
        username: str,
        display_name: str = "",
        groups: list[str] | None = None,
    ) -> tuple[User, AccountLink]:
        existing_link = self._account_link_repo.find_by_provider_and_external_id(provider.id, external_user_id)
        if existing_link:
            user = self._user_repo.find_by_id(existing_link.user_id)
            if user:
                return user, existing_link

        existing_user = self._user_repo.find_by_username(email.split("@")[0]) if provider.auto_link_users else None
        if existing_user:
            link = AccountLink(
                id=str(uuid4()),
                user_id=existing_user.id,
                provider_id=provider.id,
                external_user_id=external_user_id,
                external_username=username,
                external_email=email,
            )
            self._account_link_repo.save(link)
            return existing_user, link

        role = self._role_mapping.resolve_role(provider, groups or [])
        user = User(
            id=str(uuid4()),
            username=username or email.split("@")[0],
            email=email,
            password_hash="__sso__placeholder__",
            role=role,
            is_active=True,
        )
        from datetime import UTC, datetime
        user.created_at = datetime.now(UTC)
        self._user_repo.save(user)

        link = AccountLink(
            id=str(uuid4()),
            user_id=user.id,
            provider_id=provider.id,
            external_user_id=external_user_id,
            external_username=username,
            external_email=email,
        )
        self._account_link_repo.save(link)
        return user, link