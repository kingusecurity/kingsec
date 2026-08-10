from __future__ import annotations

from collections.abc import Callable

from sqlalchemy.orm import Session

from kingsec.application.ports.outbound.ai_provider_config_repository import (
    AIProviderConfigRecord,
    AIProviderConfigRepository,
)
from kingsec.infrastructure.persistence.models import AIProviderConfigORM

_SINGLETON_ID = "singleton"


class SQLAlchemyAIProviderConfigRepository(AIProviderConfigRepository):
    """Single-row store for the admin-configured AI provider settings.

    Same fixed-id upsert shape as ``SQLAlchemyLicenseRepository`` — there is
    exactly one active configuration, so ``save`` always writes to the same
    row rather than accumulating history.
    """

    def __init__(self, session_factory: Callable[[], Session]) -> None:
        self._session_factory = session_factory

    def get(self) -> AIProviderConfigRecord | None:
        with self._session_factory() as session:
            orm = session.get(AIProviderConfigORM, _SINGLETON_ID)
            if orm is None:
                return None
            return AIProviderConfigRecord(
                provider=orm.provider,
                api_key_encrypted=orm.api_key_encrypted,
                model=orm.model,
                base_url=orm.base_url,
                updated_at=orm.updated_at,
            )

    def save(self, record: AIProviderConfigRecord) -> None:
        with self._session_factory() as session:
            existing = session.get(AIProviderConfigORM, _SINGLETON_ID)
            if existing:
                existing.provider = record.provider
                existing.api_key_encrypted = record.api_key_encrypted
                existing.model = record.model
                existing.base_url = record.base_url
                existing.updated_at = record.updated_at
            else:
                session.add(
                    AIProviderConfigORM(
                        id=_SINGLETON_ID,
                        provider=record.provider,
                        api_key_encrypted=record.api_key_encrypted,
                        model=record.model,
                        base_url=record.base_url,
                        updated_at=record.updated_at,
                    )
                )
            session.commit()
