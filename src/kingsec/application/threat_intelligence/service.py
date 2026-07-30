from __future__ import annotations

from typing import Any

from ...domain.identifiers import CveId
from ...domain.threat_intelligence import (
    CveEntry,
    ThreatFeedEntry,
    ThreatIntelligenceSummary,
    ThreatTrendPoint,
)
from ..errors import CveNotFoundError
from .enrichment import CveEnrichmentService, EpssService, KevService
from .ports import (
    AuditPublisherPort,
    CacheServicePort,
    CveFilter,
    CveRepositoryPort,
    KevFilter,
    ThreatFeedRepositoryPort,
    TrendingThreat,
)
from .risk_calculator import ThreatRiskCalculator, ThreatRiskScore


class ThreatIntelligenceService:
    def __init__(
        self,
        cve_repo: CveRepositoryPort,
        enrichment: CveEnrichmentService,
        epss_service: EpssService,
        kev_service: KevService,
        feed_repo: ThreatFeedRepositoryPort | None = None,
        cache: CacheServicePort | None = None,
        audit: AuditPublisherPort | None = None,
    ) -> None:
        self._cve_repo = cve_repo
        self._enrichment = enrichment
        self._epss_service = epss_service
        self._kev_service = kev_service
        self._feed_repo = feed_repo
        self._cache = cache
        self._audit = audit

    async def get_summary(self) -> ThreatIntelligenceSummary:
        cache_key = "ti_summary"
        if self._cache:
            cached = await self._cache.get(cache_key)
            if cached:
                return ThreatIntelligenceSummary(**cached) if isinstance(cached, dict) else cached
        summary = self._cve_repo.get_summary()
        if self._cache:
            await self._cache.set(cache_key, {
                "total_cves": summary.total_cves,
                "critical_cves": summary.critical_cves,
                "high_cves": summary.high_cves,
                "medium_cves": summary.medium_cves,
                "low_cves": summary.low_cves,
                "kev_count": summary.kev_count,
                "active_exploitations": summary.active_exploitations,
                "average_threat_score": summary.average_threat_score,
                "average_epss_score": summary.average_epss_score,
                "feeds_active": summary.feeds_active,
                "feeds_total": summary.feeds_total,
                "trending_threats": summary.trending_threats,
                "top_critical_cves": summary.top_critical_cves,
                "recent_kev_addition_count": summary.recent_kev_additions,
            }, 120)
        return summary

    async def get_cves(self, filter_: CveFilter) -> tuple[list[CveEntry], int]:
        return self._cve_repo.find_all(filter_)

    async def get_cve_by_id(self, cve_id: CveId) -> CveEntry:
        entry = self._cve_repo.find_by_id(cve_id)
        if not entry:
            raise CveNotFoundError(f"CVE {cve_id} not found")
        return entry

    async def get_cve_by_code(self, cve_code: str) -> CveEntry:
        formatted = cve_code.upper().strip() if cve_code.upper().startswith("CVE-") else cve_code
        entry = self._cve_repo.find_by_cve_code(formatted)
        if not entry:
            enriched = await self._enrichment.enrich(formatted)
            if not enriched:
                raise CveNotFoundError(f"CVE {cve_code} not found")
            enriched.calculate_threat_score()
            self._cve_repo.save(enriched)
            if self._audit:
                await self._audit.publish("cve_enriched", "cve_entry", str(enriched.id), {"cve_code": formatted})
            return enriched
        return entry

    async def sync_cve(self, cve_code: str) -> CveEntry:
        enriched = await self._enrichment.enrich(cve_code)
        if not enriched:
            raise CveNotFoundError(f"CVE {cve_code} could not be enriched")
        enriched.calculate_threat_score()
        existing = self._cve_repo.find_by_cve_code(cve_code)
        if existing:
            enriched = CveEntry(
                cve_id=existing.id,
                cve_code=enriched.cve_code,
                description=enriched.description,
                severity=enriched.severity,
                published_date=enriched.published_date,
                last_modified=enriched.last_modified,
                cvss_data=enriched.cvss_data,
                epss_data=enriched.epss_data,
                exploit_maturity=enriched.exploit_maturity,
                affected_products=list(enriched.affected_products),
                references=list(enriched.references),
                vendor_advisories=list(enriched.vendor_advisories),
                weaknesses=list(enriched.weaknesses),
                is_kev=enriched.is_kev,
                kev_entry=enriched.kev_entry,
                threat_score=enriched.threat_score,
                exploitability_score=enriched.exploitability_score,
                priority_score=enriched.priority_score,
                created_at=existing.created_at,
            )
        saved = self._cve_repo.save(enriched)
        if self._audit:
            await self._audit.publish("cve_synced", "cve_entry", str(saved.id), {"cve_code": cve_code})
        return saved

    async def get_kev_entries(self, filter_: KevFilter) -> tuple[list[CveEntry], int]:
        return self._cve_repo.find_kev_entries(filter_)

    async def get_trending_threats(self, limit: int = 10) -> list[TrendingThreat]:
        cache_key = "ti_trending"
        if self._cache:
            cached = await self._cache.get(cache_key)
            if cached:
                cached_list: list[TrendingThreat] = cached
                return cached_list
        entries = self._cve_repo.find_trending(limit)
        result = [TrendingThreat(
            cve_code=e.cve_code,
            description=e.description[:200],
            threat_score=e.threat_score,
            severity=e.severity,
            is_kev=e.is_kev,
        ) for e in entries]
        if self._cache:
            await self._cache.set(cache_key, result, 300)
        return result

    async def get_trend_points(self, days: int = 30) -> list[ThreatTrendPoint]:
        return self._cve_repo.get_trend_points(days)

    async def get_critical_cves(self, limit: int = 10) -> list[CveEntry]:
        return self._cve_repo.find_critical(limit)

    async def get_risk_assessment(self, cve_id: CveId) -> ThreatRiskScore:
        entry = await self.get_cve_by_id(cve_id)
        return ThreatRiskCalculator.calculate(entry)

    async def delete_cve(self, cve_id: CveId) -> None:
        entry = self._cve_repo.find_by_id(cve_id)
        if not entry:
            raise CveNotFoundError(f"CVE {cve_id} not found")
        self._cve_repo.delete(cve_id)
        if self._audit:
            await self._audit.publish("cve_deleted", "cve_entry", str(cve_id), {})

    async def get_feeds(self) -> list[ThreatFeedEntry]:
        if not self._feed_repo:
            return []
        return self._feed_repo.find_all()

    async def register_feed(
        self,
        feed_type: str,
        title: str,
        source_url: str = "",
    ) -> ThreatFeedEntry:
        from datetime import UTC, datetime
        from ...domain.threat_intelligence import ThreatFeedType as TFType
        from uuid import uuid4

        ftype = TFType(feed_type) if feed_type in TFType._value2member_map_ else TFType.CUSTOM
        feed = ThreatFeedEntry(
            feed_id=uuid4().hex,
            feed_type=ftype,
            title=title,
            source_url=source_url,
            last_synced=datetime.now(UTC).isoformat(),
        )
        if self._feed_repo:
            self._feed_repo.save(feed)
        if self._audit:
            await self._audit.publish("feed_registered", "threat_feed", f"feed-{feed.feed_id}", {"type": feed_type})
        return feed

    async def get_trending_timeline(self, days: int = 30) -> list[dict[str, Any]]:
        entries = self._cve_repo.find_recent(days)
        return [
            {
                "date": e.published_date or e.created_at[:10],
                "cve_code": e.cve_code,
                "severity": e.severity,
                "threat_score": e.threat_score,
                "is_kev": e.is_kev,
                "description": e.description[:200],
            }
            for e in entries
        ]
