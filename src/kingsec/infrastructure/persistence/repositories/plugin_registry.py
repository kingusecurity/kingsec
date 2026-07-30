from __future__ import annotations

import json
import logging

from sqlalchemy import select
from sqlalchemy.orm import Session

from kingsec.domain.plugin_extensions import PluginPermission, PluginSdkManifest, PluginType
from kingsec.infrastructure.persistence.models import PluginSdkManifestModel

logger = logging.getLogger(__name__)


class SQLAlchemyPluginSdkManifestRepository:
    def __init__(self, session: Session) -> None:
        self._session = session

    def save(self, manifest: PluginSdkManifest) -> None:
        orm = self._session.get(PluginSdkManifestModel, manifest.id)
        if orm:
            orm.name = manifest.name
            orm.version = manifest.version
            orm.author = manifest.author
            orm.website = manifest.website
            orm.license = manifest.license
            orm.description = manifest.description
            orm.category = manifest.category.value
            orm.entrypoint = manifest.entrypoint
            orm.minimum_kingsec_version = manifest.minimum_kingsec_version
            orm.permissions_json = json.dumps([p.value for p in manifest.permissions])
            orm.dependencies_json = json.dumps(list(manifest.dependencies))
            orm.signature = manifest.signature
        else:
            self._session.add(PluginSdkManifestModel(
                id=manifest.id,
                name=manifest.name,
                version=manifest.version,
                author=manifest.author,
                website=manifest.website,
                license=manifest.license,
                description=manifest.description,
                category=manifest.category.value,
                entrypoint=manifest.entrypoint,
                minimum_kingsec_version=manifest.minimum_kingsec_version,
                permissions_json=json.dumps([p.value for p in manifest.permissions]),
                dependencies_json=json.dumps(list(manifest.dependencies)),
                signature=manifest.signature,
            ))

    def find_by_id(self, plugin_id: str) -> PluginSdkManifest | None:
        stmt = select(PluginSdkManifestModel).where(PluginSdkManifestModel.id == plugin_id)
        orm = self._session.execute(stmt).scalar_one_or_none()
        return self._to_domain(orm) if orm else None

    def find_all(self) -> list[PluginSdkManifest]:
        stmt = select(PluginSdkManifestModel).order_by(PluginSdkManifestModel.name)
        rows = self._session.execute(stmt).scalars().all()
        return [self._to_domain(r) for r in rows]

    def delete(self, plugin_id: str) -> None:
        orm = self._session.get(PluginSdkManifestModel, plugin_id)
        if orm:
            self._session.delete(orm)

    def count(self) -> int:
        from sqlalchemy import func
        stmt = select(func.count(PluginSdkManifestModel.id))
        return self._session.execute(stmt).scalar() or 0

    @staticmethod
    def _to_domain(orm: PluginSdkManifestModel) -> PluginSdkManifest:
        perms: list[PluginPermission] = []
        if orm.permissions_json:
            try:
                perms = [PluginPermission(p) for p in json.loads(orm.permissions_json)]
            except (json.JSONDecodeError, ValueError):
                pass
        deps: list[str] = []
        if orm.dependencies_json:
            try:
                deps = json.loads(orm.dependencies_json)
            except (json.JSONDecodeError, ValueError):
                pass
        return PluginSdkManifest(
            id=orm.id,
            name=orm.name,
            version=orm.version,
            author=orm.author,
            website=orm.website,
            license=orm.license,
            description=orm.description,
            category=PluginType(orm.category) if orm.category else PluginType.OTHER,
            entrypoint=orm.entrypoint,
            minimum_kingsec_version=orm.minimum_kingsec_version,
            permissions=tuple(perms),
            dependencies=tuple(deps),
            signature=orm.signature,
        )
