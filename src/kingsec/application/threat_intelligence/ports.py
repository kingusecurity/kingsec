from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Protocol

from ...domain.threat_intelligence import (
    CveEntry,
    CveReference,
    CvssData,
    EpssData,
    ExploitMaturity,
    KevEntry,
    ThreatFeedEntry,
    ThreatFeedType,
    ThreatIntelligenceSummary,
    ThreatTrendPoint,
)
from ...domain.identifiers import CveId, KevEntryId, ThreatFeedId


@dataclass
class CveFilter:
    search: str | None = None
    severity: str | None = None
    min_score: float | None = None
    max_score: float | None = None
    is_kev: bool | None = None
    exploit_maturity: str | None = None
    published_after: str | None = None
    published_before: str | None = None
    vendor: str | None = None
    product: str | None = None
    sort_by: str = "-threat_score"
    page: int = 1
    page_size: int = 20


@dataclass
class KevFilter:
    search: str | None = None
    known_ransomware: bool | None = None
    vendor: str | None = None
    product: str | None = None
    date_added_after: str | None = None
    due_date_before: str | None = None
    page: int = 1
    page_size: int = 20


@dataclass
class TrendingThreat:
    cve_code: str = ""
    description: str = ""
    threat_score: float = 0.0
    change: float = 0.0
    severity: str = ""
    is_kev: bool = False


class CveRepositoryPort(Protocol):
    def save(self, entry: CveEntry) -> CveEntry:
        ...

    def find_by_id(self, cve_id: CveId) -> CveEntry | None:
        ...

    def find_by_cve_code(self, cve_code: str) -> CveEntry | None:
        ...

    def find_all(self, filter_: CveFilter) -> tuple[list[CveEntry], int]:
        ...

    def find_critical(self, limit: int = 10) -> list[CveEntry]:
        ...

    def find_kev_entries(self, filter_: KevFilter) -> tuple[list[CveEntry], int]:
        ...

    def find_trending(self, limit: int = 10) -> list[CveEntry]:
        ...

    def find_recent(self, days: int = 7) -> list[CveEntry]:
        ...

    def get_summary(self) -> ThreatIntelligenceSummary:
        ...

    def get_trend_points(self, days: int = 30) -> list[ThreatTrendPoint]:
        ...

    def exists_by_cve_code(self, cve_code: str) -> bool:
        ...

    def delete(self, cve_id: CveId) -> None:
        ...

    def count(self) -> int:
        ...

    def upsert_many(self, entries: list[CveEntry]) -> list[CveEntry]:
        ...


class ThreatFeedRepositoryPort(Protocol):
    def save(self, feed: ThreatFeedEntry) -> ThreatFeedEntry:
        ...

    def find_by_id(self, feed_id: ThreatFeedId) -> ThreatFeedEntry | None:
        ...

    def find_by_type(self, feed_type: ThreatFeedType) -> ThreatFeedEntry | None:
        ...

    def find_all(self) -> list[ThreatFeedEntry]:
        ...

    def update_sync_time(self, feed_id: ThreatFeedId, timestamp: str) -> ThreatFeedEntry:
        ...

    def delete(self, feed_id: ThreatFeedId) -> None:
        ...


class NvdProviderPort(Protocol):
    async def fetch_cve(self, cve_code: str) -> dict[str, Any] | None:
        ...

    async def fetch_recent(self, days: int = 7) -> list[dict[str, Any]]:
        ...

    async def search(self, query: str, limit: int = 20) -> list[dict[str, Any]]:
        ...


class EpssProviderPort(Protocol):
    async def fetch_score(self, cve_code: str) -> EpssData | None:
        ...

    async def fetch_bulk(self, cve_codes: list[str]) -> dict[str, EpssData]:
        ...


class KevProviderPort(Protocol):
    async def fetch_all(self) -> list[dict[str, Any]]:
        ...

    async def fetch_recent(self, days: int = 7) -> list[dict[str, Any]]:
        ...

    async def fetch_by_cve(self, cve_code: str) -> dict[str, Any] | None:
        ...


class MitreCveProviderPort(Protocol):
    async def fetch_cve(self, cve_code: str) -> dict[str, Any] | None:
        ...

    async def fetch_recent(self, days: int = 7) -> list[dict[str, Any]]:
        ...


class CacheServicePort(Protocol):
    async def get(self, key: str) -> Any | None:
        ...

    async def set(self, key: str, value: Any, ttl: int = 300) -> None:
        ...

    async def delete(self, key: str) -> None:
        ...

    async def exists(self, key: str) -> bool:
        ...


class AuditPublisherPort(Protocol):
    async def publish(self, action: str, entity_type: str, entity_id: str, metadata: dict[str, Any] | None = None) -> None:
        ...
