"""Session-bound SQLAlchemy Asset repository.

Persists and retrieves :class:`Asset` value objects through the ``AssetModel``
ORM model.  The ``add`` method is insert-only (no upsert) as required by the port.
"""

from __future__ import annotations

from sqlalchemy import select
from sqlalchemy.orm import Session

from kingsec.application import AssessmentNotFoundError, AssetRepositoryPort
from kingsec.application.ports.repositories import Asset
from kingsec.infrastructure.persistence.mappers import asset_to_domain, asset_to_orm
from kingsec.infrastructure.persistence.models import AssetModel


class SQLAlchemyAssetRepository(AssetRepositoryPort):
    """Implements :class:`AssetRepositoryPort` on a caller-owned session."""

    def __init__(self, session: Session) -> None:
        self._session = session

    def add(self, asset: Asset) -> None:
        self._session.add(asset_to_orm(asset))

    def get(self, asset_id: str) -> Asset:
        orm = self._session.get(AssetModel, asset_id)
        if orm is None:
            raise AssessmentNotFoundError(asset_id)
        return asset_to_domain(orm)

    def list(
        self,
        *,
        limit: int = 50,
        offset: int = 0,
    ) -> list[Asset]:
        stmt = (
            select(AssetModel)
            .order_by(AssetModel.created_at.desc())
            .offset(offset)
            .limit(limit)
        )
        orms = self._session.execute(stmt).scalars().all()
        return [asset_to_domain(o) for o in orms]

    def exists(self, asset_id: str) -> bool:
        orm = self._session.get(AssetModel, asset_id)
        return orm is not None
