from __future__ import annotations

from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from typing import Any, Protocol

from kingsec.domain.asset import Asset, AssetHistoryEntry, AssetRelationship, AssetType


@dataclass(frozen=True)
class AssetFilter:
    asset_type: AssetType | None = None
    criticality: str | None = None
    search: str | None = None
    tag_key: str | None = None
    tag_value: str | None = None
    owner: str | None = None
    location: str | None = None
    cloud_provider: str | None = None
    has_findings: bool | None = None
    risk_score_min: float | None = None
    risk_score_max: float | None = None
    created_after: str | None = None
    created_before: str | None = None


@dataclass(frozen=True)
class AssetSummary:
    total: int
    by_type: dict[str, int]
    by_criticality: dict[str, int]
    by_risk_range: dict[str, int]
    total_open_findings: int
    total_critical_findings: int
    total_high_findings: int
    total_relationships: int


@dataclass(frozen=True)
class AssetDetail:
    asset: Asset
    relationships: list[AssetRelationship] = field(default_factory=list)
    history: list[AssetHistoryEntry] = field(default_factory=list)
    finding_count: int = 0
    critical_finding_count: int = 0
    high_finding_count: int = 0


class AssetInventoryRepositoryPort(ABC):
    @abstractmethod
    def save(self, asset: Asset) -> None:
        ...

    @abstractmethod
    def get(self, asset_id: str) -> Asset:
        ...

    @abstractmethod
    def delete(self, asset_id: str) -> None:
        ...

    @abstractmethod
    def fetch_all(self, filter_: AssetFilter | None = None, *, limit: int = 50, offset: int = 0) -> list[Asset]:
        ...

    @abstractmethod
    def count(self, filter_: AssetFilter | None = None) -> int:
        ...

    @abstractmethod
    def summary(self) -> AssetSummary:
        ...

    @abstractmethod
    def search(self, query: str, *, limit: int = 20) -> list[Asset]:
        ...

    @abstractmethod
    def save_relationship(self, rel: AssetRelationship) -> None:
        ...

    @abstractmethod
    def get_relationships(self, asset_id: str) -> list[AssetRelationship]:
        ...

    @abstractmethod
    def delete_relationship(self, source_id: str, target_id: str, rel_type: str) -> None:
        ...

    @abstractmethod
    def save_history(self, entry: AssetHistoryEntry) -> None:
        ...

    @abstractmethod
    def get_history(self, asset_id: str, *, limit: int = 50) -> list[AssetHistoryEntry]:
        ...

    @abstractmethod
    def get_by_hostname(self, hostname: str) -> Asset | None:
        ...

    @abstractmethod
    def get_by_ip(self, ip: str) -> Asset | None:
        ...

    @abstractmethod
    def get_by_domain(self, domain: str) -> Asset | None:
        ...

    @abstractmethod
    def add_finding_to_asset(self, asset_id: str, finding_id: str) -> None:
        ...

    @abstractmethod
    def get_finding_ids(self, asset_id: str) -> list[str]:
        ...


class TechnologyFingerprintPort(Protocol):
    def fingerprint(self, hostname: str, ip: str | None = None, port: int | None = None) -> list[dict[str, Any]]:
        ...


class AssetDiscoveryPort(Protocol):
    def discover(self, target: str, asset_type: AssetType) -> list[dict[str, Any]]:
        ...
