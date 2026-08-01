from __future__ import annotations

from sqlalchemy import func, or_
from sqlalchemy.orm import Session

from kingsec.application.threat_intelligence.ports import (
    CveFilter,
    CveRepositoryPort,
    KevFilter,
    ThreatFeedRepositoryPort,
)
from kingsec.domain.identifiers import CveId, ThreatFeedId
from kingsec.domain.threat_intelligence import (
    CveEntry,
    ThreatFeedEntry,
    ThreatFeedType,
    ThreatIntelligenceSummary,
    ThreatTrendPoint,
)
from kingsec.infrastructure.persistence.mappers import (
    cve_entry_to_domain,
    cve_entry_to_orm,
    threat_feed_to_domain,
    threat_feed_to_orm,
)
from kingsec.infrastructure.persistence.models import CveEntryModel, ThreatFeedModel


class SQLAlchemyCveRepository(CveRepositoryPort):
    def __init__(self, session: Session) -> None:
        self._session = session

    def save(self, entry: CveEntry) -> CveEntry:
        model = self._session.get(CveEntryModel, str(entry.id))
        orm = cve_entry_to_orm(entry)
        if model:
            for col in CveEntryModel.__table__.columns:
                setattr(model, col.name, getattr(orm, col.name))
        else:
            self._session.add(orm)
        self._session.commit()
        return entry

    def find_by_id(self, cve_id: CveId) -> CveEntry | None:
        model = self._session.get(CveEntryModel, str(cve_id))
        return cve_entry_to_domain(model) if model else None

    def find_by_cve_code(self, cve_code: str) -> CveEntry | None:
        model = self._session.query(CveEntryModel).filter(
            CveEntryModel.cve_code == cve_code.upper().strip()
        ).first()
        return cve_entry_to_domain(model) if model else None

    def find_all(self, filter_: CveFilter) -> tuple[list[CveEntry], int]:
        q = self._session.query(CveEntryModel)
        if filter_.search:
            q = q.filter(CveEntryModel.cve_code.ilike(f"%{filter_.search}%"))
        if filter_.severity:
            q = q.filter(CveEntryModel.severity == filter_.severity.upper())
        if filter_.min_score is not None:
            q = q.filter(CveEntryModel.threat_score >= filter_.min_score)
        if filter_.max_score is not None:
            q = q.filter(CveEntryModel.threat_score <= filter_.max_score)
        if filter_.is_kev is not None:
            q = q.filter(CveEntryModel.is_kev == filter_.is_kev)
        if filter_.exploit_maturity:
            q = q.filter(CveEntryModel.exploit_maturity == filter_.exploit_maturity)
        if filter_.published_after:
            q = q.filter(CveEntryModel.published_date >= filter_.published_after)
        if filter_.published_before:
            q = q.filter(CveEntryModel.published_date <= filter_.published_before)
        total = q.count()
        sort_col = getattr(CveEntryModel, filter_.sort_by.lstrip("-"), CveEntryModel.threat_score)
        if filter_.sort_by.startswith("-"):
            q = q.order_by(sort_col.desc())
        else:
            q = q.order_by(sort_col.asc())
        offset = (filter_.page - 1) * filter_.page_size
        models = q.offset(offset).limit(filter_.page_size).all()
        return [cve_entry_to_domain(m) for m in models], total

    def find_critical(self, limit: int = 10) -> list[CveEntry]:
        models = self._session.query(CveEntryModel).filter(
            CveEntryModel.severity.in_(["CRITICAL", "HIGH"])
        ).order_by(CveEntryModel.threat_score.desc()).limit(limit).all()
        return [cve_entry_to_domain(m) for m in models]

    def find_kev_entries(self, filter_: KevFilter) -> tuple[list[CveEntry], int]:
        q = self._session.query(CveEntryModel).filter(CveEntryModel.is_kev)
        if filter_.search:
            q = q.filter(
                or_(
                    CveEntryModel.cve_code.ilike(f"%{filter_.search}%"),
                    CveEntryModel.description.ilike(f"%{filter_.search}%"),
                )
            )
        if filter_.known_ransomware is not None and filter_.known_ransomware:
            q = q.filter(CveEntryModel.kev_entry_json.ilike('%"known_ransomware_campaign_use": true%'))
        if filter_.date_added_after:
            q = q.filter(CveEntryModel.published_date >= filter_.date_added_after)
        total = q.count()
        offset = (filter_.page - 1) * filter_.page_size
        models = q.order_by(CveEntryModel.threat_score.desc()).offset(offset).limit(filter_.page_size).all()
        return [cve_entry_to_domain(m) for m in models], total

    def find_trending(self, limit: int = 10) -> list[CveEntry]:
        models = self._session.query(CveEntryModel).filter(
            CveEntryModel.threat_score >= 50
        ).order_by(CveEntryModel.threat_score.desc()).limit(limit).all()
        return [cve_entry_to_domain(m) for m in models]

    def find_recent(self, days: int = 7) -> list[CveEntry]:
        from datetime import UTC, datetime, timedelta
        cutoff = (datetime.now(UTC) - timedelta(days=days)).isoformat()
        models = self._session.query(CveEntryModel).filter(
            CveEntryModel.created_at >= cutoff
        ).order_by(CveEntryModel.created_at.desc()).all()
        return [cve_entry_to_domain(m) for m in models]

    def get_summary(self) -> ThreatIntelligenceSummary:
        total = self._session.query(CveEntryModel).count()
        critical = self._session.query(CveEntryModel).filter(CveEntryModel.severity == "CRITICAL").count()
        high = self._session.query(CveEntryModel).filter(CveEntryModel.severity == "HIGH").count()
        medium = self._session.query(CveEntryModel).filter(CveEntryModel.severity == "MEDIUM").count()
        low = self._session.query(CveEntryModel).filter(CveEntryModel.severity == "LOW").count()
        kev_count = self._session.query(CveEntryModel).filter(CveEntryModel.is_kev).count()
        active_exploit = self._session.query(CveEntryModel).filter(
            CveEntryModel.exploit_maturity == "active_exploitation"
        ).count()
        avg_score = self._session.query(func.avg(CveEntryModel.threat_score)).scalar() or 0.0
        avg_epss = self._session.query(func.avg(
            func.json_extract(CveEntryModel.epss_data_json, "$.score")
        )).scalar() or 0.0
        top_critical_models = self._session.query(CveEntryModel).filter(
            CveEntryModel.severity == "CRITICAL"
        ).order_by(CveEntryModel.threat_score.desc()).limit(5).all()
        trending_models = self._session.query(CveEntryModel).filter(
            CveEntryModel.threat_score >= 50
        ).order_by(CveEntryModel.threat_score.desc()).limit(5).all()

        from datetime import UTC, datetime, timedelta
        recent_cutoff = (datetime.now(UTC) - timedelta(days=30)).isoformat()
        recent_kev = self._session.query(CveEntryModel).filter(
            CveEntryModel.is_kev,
            CveEntryModel.created_at >= recent_cutoff,
        ).count()
        feeds_active = self._session.query(ThreatFeedModel).filter(
            ThreatFeedModel.status == "active"
        ).count()
        feeds_total = self._session.query(ThreatFeedModel).count()

        return ThreatIntelligenceSummary(
            total_cves=total,
            critical_cves=critical,
            high_cves=high,
            medium_cves=medium,
            low_cves=low,
            kev_count=kev_count,
            active_exploitations=active_exploit,
            average_threat_score=round(float(avg_score), 2),
            average_epss_score=round(float(avg_epss), 4),
            feeds_active=feeds_active,
            feeds_total=feeds_total,
            trending_threats=[
                {"cve_code": m.cve_code, "threat_score": m.threat_score, "severity": m.severity, "is_kev": m.is_kev}
                for m in trending_models
            ],
            top_critical_cves=[
                {"cve_code": m.cve_code, "threat_score": m.threat_score, "description": m.description[:200]}
                for m in top_critical_models
            ],
            recent_kev_additions=recent_kev,
        )

    def get_trend_points(self, days: int = 30) -> list[ThreatTrendPoint]:
        from datetime import UTC, datetime, timedelta
        cutoff = (datetime.now(UTC) - timedelta(days=days)).isoformat()
        models = self._session.query(CveEntryModel).filter(
            CveEntryModel.created_at >= cutoff
        ).order_by(CveEntryModel.created_at.asc()).all()

        day_buckets: dict[str, list[CveEntryModel]] = {}
        for m in models:
            day = m.created_at[:10] if m.created_at else ""
            if day not in day_buckets:
                day_buckets[day] = []
            day_buckets[day].append(m)

        return [
            ThreatTrendPoint(
                date=day,
                new_cves=len(items),
                critical_cves=sum(1 for it in items if it.severity == "CRITICAL"),
                kev_additions=sum(1 for it in items if it.is_kev),
                average_score=round(float(sum(it.threat_score for it in items) / len(items)), 2) if items else 0.0,
            )
            for day, items in sorted(day_buckets.items())
        ]

    def exists_by_cve_code(self, cve_code: str) -> bool:
        return self._session.query(CveEntryModel).filter(
            CveEntryModel.cve_code == cve_code.upper().strip()
        ).first() is not None

    def delete(self, cve_id: CveId) -> None:
        model = self._session.get(CveEntryModel, str(cve_id))
        if model:
            self._session.delete(model)
            self._session.commit()

    def count(self) -> int:
        return self._session.query(CveEntryModel).count()

    def upsert_many(self, entries: list[CveEntry]) -> list[CveEntry]:
        results: list[CveEntry] = []
        for entry in entries:
            results.append(self.save(entry))
        return results


class SQLAlchemyThreatFeedRepository(ThreatFeedRepositoryPort):
    def __init__(self, session: Session) -> None:
        self._session = session

    def save(self, feed: ThreatFeedEntry) -> ThreatFeedEntry:
        model = self._session.get(ThreatFeedModel, feed.feed_id)
        orm = threat_feed_to_orm(feed)
        if model:
            for col in ThreatFeedModel.__table__.columns:
                setattr(model, col.name, getattr(orm, col.name))
        else:
            self._session.add(orm)
        self._session.commit()
        return feed

    def find_by_id(self, feed_id: ThreatFeedId) -> ThreatFeedEntry | None:
        model = self._session.get(ThreatFeedModel, str(feed_id))
        return threat_feed_to_domain(model) if model else None

    def find_by_type(self, feed_type: ThreatFeedType) -> ThreatFeedEntry | None:
        model = self._session.query(ThreatFeedModel).filter(
            ThreatFeedModel.feed_type == feed_type.value
        ).first()
        return threat_feed_to_domain(model) if model else None

    def find_all(self) -> list[ThreatFeedEntry]:
        models = self._session.query(ThreatFeedModel).all()
        return [threat_feed_to_domain(m) for m in models]

    def update_sync_time(self, feed_id: ThreatFeedId, timestamp: str) -> ThreatFeedEntry:
        model = self._session.get(ThreatFeedModel, str(feed_id))
        if model:
            model.last_synced = timestamp
            self._session.commit()
            return threat_feed_to_domain(model)
        raise ValueError(f"Feed {feed_id} not found")

    def delete(self, feed_id: ThreatFeedId) -> None:
        model = self._session.get(ThreatFeedModel, str(feed_id))
        if model:
            self._session.delete(model)
            self._session.commit()
