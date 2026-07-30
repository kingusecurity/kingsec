from __future__ import annotations

from typing import Any

from ...domain.threat_intelligence import (
    CveEntry,
    EpssData,
    KevEntry,
    ThreatFeedEntry,
    ThreatFeedType,
)
from .ports import (
    AuditPublisherPort,
    CacheServicePort,
    EpssProviderPort,
    KevProviderPort,
    MitreCveProviderPort,
    NvdProviderPort,
    ThreatFeedRepositoryPort,
)


class ThreatFeedAggregator:
    def __init__(
        self,
        nvd_provider: NvdProviderPort | None = None,
        kev_provider: KevProviderPort | None = None,
        epss_provider: EpssProviderPort | None = None,
        mitre_provider: MitreCveProviderPort | None = None,
        feed_repo: ThreatFeedRepositoryPort | None = None,
        cache: CacheServicePort | None = None,
        audit: AuditPublisherPort | None = None,
    ) -> None:
        self._nvd = nvd_provider
        self._kev = kev_provider
        self._epss = epss_provider
        self._mitre = mitre_provider
        self._feed_repo = feed_repo
        self._cache = cache
        self._audit = audit

    async def sync_nvd_feed(self, days: int = 7) -> list[CveEntry]:
        if not self._nvd:
            return []
        cache_key = f"nvd_sync_{days}"
        if self._cache and await self._cache.exists(cache_key):
            return []
        raw = await self._nvd.fetch_recent(days)
        entries = self._convert_nvd(raw)
        if self._cache and raw:
            await self._cache.set(cache_key, True, 900)
        if self._audit:
            await self._audit.publish("feed_sync", "nvd", f"nvd-{days}", {"entries": len(entries)})
        return entries

    async def sync_kev_feed(self, days: int = 7) -> list[KevEntry]:
        if not self._kev:
            return []
        cache_key = f"kev_sync_{days}"
        if self._cache and await self._cache.exists(cache_key):
            return []
        raw = await self._kev.fetch_recent(days)
        entries = [self._convert_kev(r) for r in raw]
        if self._cache and raw:
            await self._cache.set(cache_key, True, 900)
        if self._audit:
            await self._audit.publish("feed_sync", "cisa_kev", f"kev-{days}", {"entries": len(entries)})
        return entries

    async def sync_epss_scores(self, cve_codes: list[str]) -> dict[str, EpssData]:
        if not self._epss or not cve_codes:
            return {}
        cache_key = "epss_bulk_sync"
        if self._cache and await self._cache.exists(cache_key):
            return {}
        result = await self._epss.fetch_bulk(cve_codes)
        if self._cache and result:
            await self._cache.set(cache_key, True, 300)
        if self._audit:
            await self._audit.publish("feed_sync", "epss", "epss-bulk", {"cves": len(cve_codes)})
        return result

    async def sync_mitre_feed(self, days: int = 7) -> list[CveEntry]:
        if not self._mitre:
            return []
        cache_key = f"mitre_sync_{days}"
        if self._cache and await self._cache.exists(cache_key):
            return []
        raw = await self._mitre.fetch_recent(days)
        entries = self._convert_nvd(raw)
        if self._cache and raw:
            await self._cache.set(cache_key, True, 900)
        if self._audit:
            await self._audit.publish("feed_sync", "mitre_cve", f"mitre-{days}", {"entries": len(entries)})
        return entries

    async def register_feed(self, feed_type: str, title: str, source_url: str = "") -> ThreatFeedEntry:
        from datetime import UTC, datetime

        ftype = ThreatFeedType(feed_type) if feed_type in ThreatFeedType._value2member_map_ else ThreatFeedType.CUSTOM
        feed = ThreatFeedEntry(
            feed_id=ThreatFeedType.generate() if hasattr(ThreatFeedType, "generate") else f"feed-{uuid_hex()}",
            feed_type=ftype,
            title=title,
            source_url=source_url,
            last_synced=datetime.now(UTC).isoformat(),
        )
        if self._feed_repo:
            self._feed_repo.save(feed)
        if self._audit:
            await self._audit.publish("feed_register", "threat_feed", feed.feed_id, {"type": feed_type})
        return feed

    def _convert_nvd(self, raw: list[dict[str, Any]]) -> list[CveEntry]:
        return []

    def _convert_kev(self, raw: dict[str, Any]) -> KevEntry:
        return KevEntry(
            id=raw.get("id", ""),
            cve_id=raw.get("cveID", raw.get("cve_id", "")),
            vendor_project=raw.get("vendorProject", raw.get("vendor_project", "")),
            product=raw.get("product", ""),
            vulnerability_name=raw.get("vulnerabilityName", raw.get("vulnerability_name", "")),
            date_added=raw.get("dateAdded", raw.get("date_added", "")),
            due_date=raw.get("dueDate", raw.get("due_date", "")),
            required_action=raw.get("requiredAction", raw.get("required_action", "")),
            known_ransomware_campaign_use=bool(
                raw.get("knownRansomwareCampaignUse", raw.get("known_ransomware_campaign_use", False))
            ),
            notes=raw.get("notes", ""),
        )


def uuid_hex() -> str:
    from uuid import uuid4
    return uuid4().hex
