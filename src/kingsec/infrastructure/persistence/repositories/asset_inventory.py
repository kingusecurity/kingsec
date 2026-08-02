from __future__ import annotations

import json
from collections.abc import Callable
from datetime import UTC, datetime
from typing import Any

from sqlalchemy import Select, func, or_, select
from sqlalchemy.orm import Session

from kingsec.application.errors import AssetNotFoundError
from kingsec.application.ports.asset_inventory import (
    AssetFilter,
    AssetInventoryRepositoryPort,
    AssetSummary,
)
from kingsec.domain.asset import Asset, AssetHistoryEntry, AssetRelationship
from kingsec.infrastructure.persistence.mappers import (
    inventory_asset_to_domain,
    inventory_asset_to_orm,
)
from kingsec.infrastructure.persistence.models import (
    AssetHistoryModel,
    AssetModel,
    AssetRelationshipModel,
    AssetTagModel,
    AssetTechnologyModel,
    FindingModel,
)


class SQLAlchemyAssetInventoryRepository(AssetInventoryRepositoryPort):
    def __init__(self, session_factory: Callable[[], Session]) -> None:
        self._session_factory = session_factory

    def save(self, asset: Asset) -> None:
        with self._session_factory() as session:
            orm = session.get(AssetModel, str(asset.id))
            if orm:
                _update_orm_from_domain(orm, asset)
            else:
                orm = inventory_asset_to_orm(asset)
                session.add(orm)
            session.flush()
            _sync_tags(session, orm, asset)
            _sync_technologies(session, orm, asset)
            session.commit()

    def get(self, asset_id: str) -> Asset:
        with self._session_factory() as session:
            orm = session.get(AssetModel, asset_id)
            if orm is None:
                raise AssetNotFoundError(f"Asset not found: {asset_id}")
            return inventory_asset_to_domain(orm)

    def delete(self, asset_id: str) -> None:
        with self._session_factory() as session:
            orm = session.get(AssetModel, asset_id)
            if orm:
                session.delete(orm)
                session.commit()

    def fetch_all(
        self,
        filter_: AssetFilter | None = None,
        *,
        limit: int = 50,
        offset: int = 0,
    ) -> list[Asset]:
        query = select(AssetModel)
        query = _apply_filter(query, filter_)
        query = query.order_by(AssetModel.updated_at.desc()).offset(offset).limit(limit)
        with self._session_factory() as session:
            orms = session.execute(query).scalars().all()
            return [inventory_asset_to_domain(o) for o in orms]

    def count(self, filter_: AssetFilter | None = None) -> int:
        query = select(func.count(AssetModel.id))
        query = _apply_filter(query, filter_)
        with self._session_factory() as session:
            result = session.execute(query).scalar()
            return result or 0

    def summary(self) -> AssetSummary:
        with self._session_factory() as session:
            total = session.execute(select(func.count(AssetModel.id))).scalar() or 0

            type_rows = session.execute(
                select(AssetModel.asset_type, func.count(AssetModel.id))
                .group_by(AssetModel.asset_type)
            ).all()
            by_type = {row[0]: row[1] for row in type_rows}

            crit_rows = session.execute(
                select(AssetModel.criticality, func.count(AssetModel.id))
                .group_by(AssetModel.criticality)
            ).all()
            by_criticality = {row[0] or "unknown": row[1] for row in crit_rows}

            risk_ranges = {
                "none": 0, "low": 0, "medium": 0, "high": 0, "critical": 0,
            }
            risk_rows = session.execute(
                select(AssetModel.risk_score, AssetModel.id)
            ).all()
            for score, _ in risk_rows:
                if score == 0:
                    risk_ranges["none"] += 1
                elif score < 25:
                    risk_ranges["low"] += 1
                elif score < 50:
                    risk_ranges["medium"] += 1
                elif score < 75:
                    risk_ranges["high"] += 1
                else:
                    risk_ranges["critical"] += 1

            total_rel = session.execute(
                select(func.count(AssetRelationshipModel.id))
            ).scalar() or 0

            total_findings = session.execute(
                select(func.count(FindingModel.id))
            ).scalar() or 0
            total_crit = session.execute(
                select(func.count(FindingModel.id)).where(FindingModel.severity == "critical")
            ).scalar() or 0
            total_high = session.execute(
                select(func.count(FindingModel.id)).where(FindingModel.severity == "high")
            ).scalar() or 0

            return AssetSummary(
                total=total,
                by_type=by_type,
                by_criticality=by_criticality,
                by_risk_range=risk_ranges,
                total_open_findings=total_findings,
                total_critical_findings=total_crit,
                total_high_findings=total_high,
                total_relationships=total_rel,
            )

    def search(self, query: str, *, limit: int = 20) -> list[Asset]:
        pattern = f"%{query}%"
        stmt = (
            select(AssetModel)
            .where(
                or_(
                    AssetModel.hostname.ilike(pattern),
                    AssetModel.ip_address.ilike(pattern),
                    AssetModel.domain.ilike(pattern),
                    AssetModel.fqdn.ilike(pattern),
                    AssetModel.mac_address.ilike(pattern),
                    AssetModel.owner.ilike(pattern),
                    AssetModel.description.ilike(pattern),
                )
            )
            .limit(limit)
        )
        with self._session_factory() as session:
            orms = session.execute(stmt).scalars().all()
            return [inventory_asset_to_domain(o) for o in orms]

    def save_relationship(self, rel: AssetRelationship) -> None:
        with self._session_factory() as session:
            existing = session.execute(
                select(AssetRelationshipModel).where(
                    AssetRelationshipModel.source_asset_id == rel.source_asset_id,
                    AssetRelationshipModel.target_asset_id == rel.target_asset_id,
                    AssetRelationshipModel.relationship_type == rel.relationship_type,
                )
            ).scalar_one_or_none()
            if existing:
                existing.metadata_json = json.dumps(rel.metadata) if rel.metadata else None
            else:
                orm = AssetRelationshipModel(
                    source_asset_id=rel.source_asset_id,
                    target_asset_id=rel.target_asset_id,
                    relationship_type=rel.relationship_type,
                    metadata_json=json.dumps(rel.metadata) if rel.metadata else None,
                )
                session.add(orm)
            session.commit()

    def get_relationships(self, asset_id: str) -> list[AssetRelationship]:
        stmt = select(AssetRelationshipModel).where(
            or_(
                AssetRelationshipModel.source_asset_id == asset_id,
                AssetRelationshipModel.target_asset_id == asset_id,
            )
        )
        with self._session_factory() as session:
            orms = session.execute(stmt).scalars().all()
            result: list[AssetRelationship] = []
            for o in orms:
                meta: dict[str, object] = {}
                if o.metadata_json:
                    try:
                        meta = json.loads(o.metadata_json)
                    except (json.JSONDecodeError, TypeError):
                        pass
                result.append(
                    AssetRelationship(
                        source_asset_id=o.source_asset_id,
                        target_asset_id=o.target_asset_id,
                        relationship_type=o.relationship_type,
                        metadata=meta,
                    )
                )
            return result

    def delete_relationship(self, source_id: str, target_id: str, rel_type: str) -> None:
        with self._session_factory() as session:
            orm = session.execute(
                select(AssetRelationshipModel).where(
                    AssetRelationshipModel.source_asset_id == source_id,
                    AssetRelationshipModel.target_asset_id == target_id,
                    AssetRelationshipModel.relationship_type == rel_type,
                )
            ).scalar_one_or_none()
            if orm:
                session.delete(orm)
                session.commit()

    def save_history(self, entry: AssetHistoryEntry) -> None:
        orm = AssetHistoryModel(
            asset_id=entry.asset_id,
            event_type=entry.event_type,
            description=entry.description,
            timestamp=entry.timestamp,
            previous_value=entry.previous_value,
            new_value=entry.new_value,
            actor=entry.actor,
            metadata_json=json.dumps(entry.metadata) if entry.metadata else None,
        )
        with self._session_factory() as session:
            session.add(orm)
            session.commit()

    def get_history(self, asset_id: str, *, limit: int = 50) -> list[AssetHistoryEntry]:
        stmt = (
            select(AssetHistoryModel)
            .where(AssetHistoryModel.asset_id == asset_id)
            .order_by(AssetHistoryModel.timestamp.desc())
            .limit(limit)
        )
        with self._session_factory() as session:
            orms = session.execute(stmt).scalars().all()
            result: list[AssetHistoryEntry] = []
            for o in orms:
                meta: dict[str, object] = {}
                if o.metadata_json:
                    try:
                        meta = json.loads(o.metadata_json)
                    except (json.JSONDecodeError, TypeError):
                        pass
                result.append(
                    AssetHistoryEntry(
                        asset_id=o.asset_id,
                        event_type=o.event_type,
                        description=o.description,
                        timestamp=o.timestamp,
                        previous_value=o.previous_value,
                        new_value=o.new_value,
                        actor=o.actor,
                        metadata=meta,
                    )
                )
            return result

    def get_by_hostname(self, hostname: str) -> Asset | None:
        with self._session_factory() as session:
            orm = session.execute(
                select(AssetModel).where(AssetModel.hostname == hostname)
            ).scalar_one_or_none()
            return inventory_asset_to_domain(orm) if orm else None

    def get_by_ip(self, ip: str) -> Asset | None:
        with self._session_factory() as session:
            orm = session.execute(
                select(AssetModel).where(AssetModel.ip_address == ip)
            ).scalar_one_or_none()
            return inventory_asset_to_domain(orm) if orm else None

    def get_by_domain(self, domain: str) -> Asset | None:
        with self._session_factory() as session:
            orm = session.execute(
                select(AssetModel).where(AssetModel.domain == domain)
            ).scalar_one_or_none()
            return inventory_asset_to_domain(orm) if orm else None

    def add_finding_to_asset(self, asset_id: str, finding_id: str) -> None:
        stmt = select(FindingModel).where(FindingModel.id == finding_id)
        with self._session_factory() as session:
            finding = session.execute(stmt).scalar_one_or_none()
            if finding:
                finding.asset_id = asset_id
                session.commit()

    def get_finding_ids(self, asset_id: str) -> list[str]:
        stmt = select(FindingModel.id).where(FindingModel.asset_id == asset_id)
        with self._session_factory() as session:
            rows = session.execute(stmt).scalars().all()
            return list(rows)


def _update_orm_from_domain(orm: AssetModel, asset: Asset) -> None:
    import json
    orm.asset_type = asset.asset_type.value
    orm.hostname = asset.hostname
    orm.ip_address = asset.ip_address
    orm.domain = asset.domain
    orm.fqdn = asset.fqdn
    orm.mac_address = asset.mac_address
    orm.operating_system = asset.operating_system
    orm.os_version = asset.os_version
    orm.owner = asset.owner
    orm.criticality = asset.criticality.value
    orm.location = asset.location
    orm.description = asset.description
    orm.open_ports = json.dumps(asset.open_ports) if asset.open_ports else None
    orm.certificate_issuer = asset.certificate_issuer
    orm.certificate_expiry = asset.certificate_expiry
    orm.tls_version = asset.tls_version
    orm.cloud_provider = asset.cloud_provider
    orm.cloud_region = asset.cloud_region
    orm.container_runtime = asset.container_runtime
    orm.container_image = asset.container_image
    orm.database_type = asset.database_type
    orm.database_version = asset.database_version
    orm.web_server = asset.web_server
    orm.programming_language = asset.programming_language
    orm.framework = asset.framework
    orm.cms = asset.cms
    orm.first_seen = asset.first_seen
    orm.last_seen = asset.last_seen
    orm.risk_score = asset.risk_score
    orm.metadata_json = json.dumps(asset.metadata) if asset.metadata else None
    orm.updated_at = datetime.now(UTC).isoformat()


def _sync_tags(session: Session, orm: AssetModel, asset: Asset) -> None:
    existing = {t.key: t for t in (orm.tags or [])}
    for tag in asset.tags:
        if tag.key in existing:
            if existing[tag.key].value != tag.value:
                existing[tag.key].value = tag.value
        else:
            session.add(AssetTagModel(asset_id=str(asset.id), key=tag.key, value=tag.value))
    new_keys = {t.key for t in asset.tags}
    for t in list(orm.tags or []):
        if t.key not in new_keys:
            session.delete(t)


def _sync_technologies(session: Session, orm: AssetModel, asset: Asset) -> None:
    existing = {(t.technology_type, t.name): t for t in (orm.technologies or [])}
    for tech in asset.technologies:
        key = (tech.technology_type, tech.name)
        if key in existing:
            e = existing[key]
            e.version = tech.version
            e.vendor = tech.vendor
            e.confidence = tech.confidence
        else:
            session.add(
                AssetTechnologyModel(
                    asset_id=str(asset.id),
                    technology_type=tech.technology_type,
                    name=tech.name,
                    version=tech.version,
                    vendor=tech.vendor,
                    confidence=tech.confidence,
                )
            )
    new_keys = {(t.technology_type, t.name) for t in asset.technologies}
    for t in list(orm.technologies or []):
        if (t.technology_type, t.name) not in new_keys:
            session.delete(t)


def _apply_filter(query: Select[Any], filter_: AssetFilter | None) -> Select[Any]:
    if filter_ is None:
        return query
    q = query
    if filter_.asset_type:
        q = q.where(AssetModel.asset_type == filter_.asset_type.value)
    if filter_.criticality:
        q = q.where(AssetModel.criticality == filter_.criticality)
    if filter_.search:
        pattern = f"%{filter_.search}%"
        q = q.where(
            or_(
                AssetModel.hostname.ilike(pattern),
                AssetModel.ip_address.ilike(pattern),
                AssetModel.domain.ilike(pattern),
                AssetModel.fqdn.ilike(pattern),
                AssetModel.owner.ilike(pattern),
                AssetModel.description.ilike(pattern),
            )
        )
    if filter_.tag_key:
        q = q.where(AssetModel.tags.any(AssetTagModel.key == filter_.tag_key))
    if filter_.tag_value:
        q = q.where(AssetModel.tags.any(AssetTagModel.value == filter_.tag_value))
    if filter_.owner:
        q = q.where(AssetModel.owner == filter_.owner)
    if filter_.location:
        q = q.where(AssetModel.location == filter_.location)
    if filter_.cloud_provider:
        q = q.where(AssetModel.cloud_provider == filter_.cloud_provider)
    if filter_.risk_score_min is not None:
        q = q.where(AssetModel.risk_score >= filter_.risk_score_min)
    if filter_.risk_score_max is not None:
        q = q.where(AssetModel.risk_score <= filter_.risk_score_max)
    if filter_.created_after:
        q = q.where(AssetModel.created_at >= filter_.created_after)
    if filter_.created_before:
        q = q.where(AssetModel.created_at <= filter_.created_before)
    return q
