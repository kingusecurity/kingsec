from __future__ import annotations

import json
from datetime import UTC, datetime, timedelta
from typing import Any

from sqlalchemy import Select, func, or_, select
from sqlalchemy.orm import Session

from kingsec.application.errors import ExposureNotFoundError
from kingsec.application.ports.attack_surface import (
    AttackSurfaceRepositoryPort,
    AttackSurfaceSummary,
    ExposureFilter,
)
from kingsec.domain.attack_surface import Exposure, ExposureHistoryEntry, ExposureSeverity, ExposureType
from kingsec.domain.identifiers import AttackSurfaceId
from kingsec.infrastructure.persistence.mappers import exposure_to_domain, exposure_to_orm
from kingsec.infrastructure.persistence.models import AssetModel, ExposureHistoryModel, ExposureModel


class SQLAlchemyAttackSurfaceRepository(AttackSurfaceRepositoryPort):
    def __init__(self, session: Session) -> None:
        self._session = session

    def save(self, exposure: Exposure) -> None:
        orm = self._session.get(ExposureModel, str(exposure.id))
        if orm:
            _update_exposure_orm(orm, exposure)
        else:
            orm = exposure_to_orm(exposure)
            self._session.add(orm)
        self._session.flush()

    def get(self, exposure_id: str) -> Exposure:
        orm = self._session.get(ExposureModel, exposure_id)
        if orm is None:
            raise ExposureNotFoundError(f"Exposure not found: {exposure_id}")
        return exposure_to_domain(orm)

    def delete(self, exposure_id: str) -> None:
        orm = self._session.get(ExposureModel, exposure_id)
        if orm:
            self._session.delete(orm)

    def fetch_all(
        self,
        filter_: ExposureFilter | None = None,
        *,
        limit: int = 50,
        offset: int = 0,
    ) -> list[Exposure]:
        query = select(ExposureModel)
        query = _apply_exposure_filter(query, filter_)
        query = query.order_by(ExposureModel.risk_score.desc()).offset(offset).limit(limit)
        orms = self._session.execute(query).scalars().all()
        return [exposure_to_domain(o) for o in orms]

    def count(self, filter_: ExposureFilter | None = None) -> int:
        query = select(func.count(ExposureModel.id))
        query = _apply_exposure_filter(query, filter_)
        result = self._session.execute(query).scalar()
        return result or 0

    def summary(self) -> AttackSurfaceSummary:
        total = self._session.execute(select(func.count(ExposureModel.id))).scalar() or 0

        severity_rows = self._session.execute(
            select(ExposureModel.severity, func.count(ExposureModel.id))
            .group_by(ExposureModel.severity)
        ).all()
        by_severity = {row[0]: row[1] for row in severity_rows}

        type_rows = self._session.execute(
            select(ExposureModel.exposure_type, func.count(ExposureModel.id))
            .group_by(ExposureModel.exposure_type)
        ).all()
        by_type = {row[0]: row[1] for row in type_rows}

        status_rows = self._session.execute(
            select(ExposureModel.status, func.count(ExposureModel.id))
            .group_by(ExposureModel.status)
        ).all()
        by_status = {row[0]: row[1] for row in status_rows}

        source_rows = self._session.execute(
            select(ExposureModel.source, func.count(ExposureModel.id))
            .group_by(ExposureModel.source)
        ).all()
        by_source = {row[0]: row[1] for row in source_rows}

        avg_risk = self._session.execute(select(func.avg(ExposureModel.risk_score))).scalar() or 0.0

        asset_count = self._session.execute(
            select(func.count(func.distinct(ExposureModel.asset_id)))
        ).scalar() or 0

        top_rows = (
            self._session.execute(
                select(ExposureModel)
                .where(ExposureModel.status == "active")
                .order_by(ExposureModel.risk_score.desc())
                .limit(10)
            )
            .scalars()
            .all()
        )
        top_risk = [
            {"id": r.id, "title": r.title, "type": r.exposure_type, "severity": r.severity, "risk_score": r.risk_score}
            for r in top_rows
        ]

        return AttackSurfaceSummary(
            total_exposures=total,
            by_severity=by_severity,
            by_type=by_type,
            by_status=by_status,
            by_source=by_source,
            critical_count=by_severity.get("critical", 0),
            high_count=by_severity.get("high", 0),
            medium_count=by_severity.get("medium", 0),
            low_count=by_severity.get("low", 0),
            info_count=by_severity.get("info", 0),
            mitigated_count=by_status.get("mitigated", 0),
            average_risk_score=round(float(avg_risk), 2),
            total_assets_affected=asset_count,
            top_risk_items=top_risk,
        )

    def get_by_asset(self, asset_id: str, *, limit: int = 50, offset: int = 0) -> list[Exposure]:
        stmt = (
            select(ExposureModel)
            .where(ExposureModel.asset_id == asset_id)
            .order_by(ExposureModel.risk_score.desc())
            .offset(offset)
            .limit(limit)
        )
        orms = self._session.execute(stmt).scalars().all()
        return [exposure_to_domain(o) for o in orms]

    def count_by_asset(self, asset_id: str) -> int:
        stmt = select(func.count(ExposureModel.id)).where(ExposureModel.asset_id == asset_id)
        result = self._session.execute(stmt).scalar()
        return result or 0

    def get_by_type(self, exposure_type: ExposureType) -> list[Exposure]:
        stmt = select(ExposureModel).where(ExposureModel.exposure_type == exposure_type.value)
        orms = self._session.execute(stmt).scalars().all()
        return [exposure_to_domain(o) for o in orms]

    def get_high_risk(self, min_score: float = 50.0) -> list[Exposure]:
        stmt = (
            select(ExposureModel)
            .where(ExposureModel.risk_score >= min_score, ExposureModel.status == "active")
            .order_by(ExposureModel.risk_score.desc())
        )
        orms = self._session.execute(stmt).scalars().all()
        return [exposure_to_domain(o) for o in orms]

    def search(self, query: str, *, limit: int = 20) -> list[Exposure]:
        pattern = f"%{query}%"
        stmt = (
            select(ExposureModel)
            .where(
                or_(
                    ExposureModel.title.ilike(pattern),
                    ExposureModel.description.ilike(pattern),
                    ExposureModel.hostname.ilike(pattern),
                    ExposureModel.ip_address.ilike(pattern),
                    ExposureModel.domain.ilike(pattern),
                    ExposureModel.url.ilike(pattern),
                )
            )
            .limit(limit)
        )
        orms = self._session.execute(stmt).scalars().all()
        return [exposure_to_domain(o) for o in orms]

    def save_history(self, entry: ExposureHistoryEntry) -> None:
        orm = ExposureHistoryModel(
            exposure_id=entry.exposure_id,
            event_type=entry.event_type,
            description=entry.description,
            timestamp=entry.timestamp,
            previous_value=entry.previous_value,
            new_value=entry.new_value,
            actor=entry.actor,
        )
        self._session.add(orm)

    def get_history(self, exposure_id: str, *, limit: int = 50) -> list[ExposureHistoryEntry]:
        stmt = (
            select(ExposureHistoryModel)
            .where(ExposureHistoryModel.exposure_id == exposure_id)
            .order_by(ExposureHistoryModel.timestamp.desc())
            .limit(limit)
        )
        orms = self._session.execute(stmt).scalars().all()
        return [
            ExposureHistoryEntry(
                exposure_id=o.exposure_id,
                event_type=o.event_type,
                description=o.description,
                timestamp=o.timestamp,
                previous_value=o.previous_value,
                new_value=o.new_value,
                actor=o.actor,
            )
            for o in orms
        ]

    def get_trend_data(self, days: int = 30) -> list[dict[str, Any]]:
        cutoff = (datetime.now(UTC) - timedelta(days=days)).isoformat()
        stmt = (
            select(ExposureModel.severity, ExposureModel.created_at)
            .where(ExposureModel.created_at >= cutoff)
            .order_by(ExposureModel.created_at)
        )
        rows = self._session.execute(stmt).all()
        daily: dict[str, dict[str, int]] = {}
        for severity, created_at in rows:
            day = created_at[:10]
            if day not in daily:
                daily[day] = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}
            daily[day][severity] = daily[day].get(severity, 0) + 1
        return [
            {
                "date": day,
                "critical": counts["critical"],
                "high": counts["high"],
                "medium": counts["medium"],
                "low": counts["low"],
                "info": counts["info"],
                "total": sum(counts.values()),
            }
            for day, counts in sorted(daily.items())
        ]

    def mark_mitigated(self, exposure_id: str) -> None:
        orm = self._session.get(ExposureModel, exposure_id)
        if orm:
            orm.status = "mitigated"

    def get_assets_with_exposures(self) -> list[str]:
        stmt = select(func.distinct(ExposureModel.asset_id)).where(ExposureModel.status == "active")
        rows = self._session.execute(stmt).scalars().all()
        return list(rows)


def _update_exposure_orm(orm: ExposureModel, exposure: Exposure) -> None:
    import json
    orm.exposure_type = exposure.exposure_type.value
    orm.severity = exposure.severity.value
    orm.title = exposure.title
    orm.description = exposure.description
    orm.detail_json = json.dumps([{"key": d.key, "value": d.value, "metadata": d.metadata} for d in exposure.detail]) if exposure.detail else None
    orm.status = exposure.status.value
    orm.source = exposure.source
    orm.port = exposure.port
    orm.protocol = exposure.protocol
    orm.hostname = exposure.hostname
    orm.ip_address = exposure.ip_address
    orm.domain = exposure.domain
    orm.url = exposure.url
    orm.tls_version = exposure.tls_version
    orm.certificate_issuer = exposure.certificate_issuer
    orm.certificate_expiry = exposure.certificate_expiry
    orm.header_name = exposure.header_name
    orm.header_value = exposure.header_value
    orm.technology_name = exposure.technology_name
    orm.technology_version = exposure.technology_version
    orm.cloud_provider = exposure.cloud_provider
    orm.cloud_bucket = exposure.cloud_bucket
    orm.evidence = exposure.evidence
    orm.remediation = exposure.remediation
    orm.risk_score = exposure.risk_score
    orm.metadata_json = json.dumps(exposure.metadata) if exposure.metadata else None
    orm.first_seen = exposure.first_seen
    orm.last_seen = exposure.last_seen
    orm.updated_at = datetime.now(UTC).isoformat()


def _apply_exposure_filter(query: Select[Any], filter_: ExposureFilter | None) -> Select[Any]:
    if filter_ is None:
        return query
    q = query
    if filter_.asset_id:
        q = q.where(ExposureModel.asset_id == filter_.asset_id)
    if filter_.exposure_type:
        q = q.where(ExposureModel.exposure_type == filter_.exposure_type.value)
    if filter_.severity:
        q = q.where(ExposureModel.severity == filter_.severity.value)
    if filter_.status:
        q = q.where(ExposureModel.status == filter_.status)
    if filter_.source:
        q = q.where(ExposureModel.source == filter_.source)
    if filter_.search:
        pattern = f"%{filter_.search}%"
        q = q.where(
            or_(
                ExposureModel.title.ilike(pattern),
                ExposureModel.description.ilike(pattern),
                ExposureModel.hostname.ilike(pattern),
                ExposureModel.ip_address.ilike(pattern),
                ExposureModel.domain.ilike(pattern),
            )
        )
    if filter_.risk_score_min is not None:
        q = q.where(ExposureModel.risk_score >= filter_.risk_score_min)
    if filter_.risk_score_max is not None:
        q = q.where(ExposureModel.risk_score <= filter_.risk_score_max)
    if filter_.created_after:
        q = q.where(ExposureModel.created_at >= filter_.created_after)
    if filter_.created_before:
        q = q.where(ExposureModel.created_at <= filter_.created_before)
    return q
