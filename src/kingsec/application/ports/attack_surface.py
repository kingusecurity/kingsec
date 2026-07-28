from __future__ import annotations

from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from typing import Any

from kingsec.domain.attack_surface import Exposure, ExposureHistoryEntry, ExposureSeverity, ExposureType


@dataclass(frozen=True)
class ExposureFilter:
    asset_id: str | None = None
    exposure_type: ExposureType | None = None
    severity: ExposureSeverity | None = None
    status: str | None = None
    source: str | None = None
    search: str | None = None
    risk_score_min: float | None = None
    risk_score_max: float | None = None
    created_after: str | None = None
    created_before: str | None = None


@dataclass(frozen=True)
class AttackSurfaceSummary:
    total_exposures: int
    by_severity: dict[str, int]
    by_type: dict[str, int]
    by_status: dict[str, int]
    by_source: dict[str, int]
    critical_count: int
    high_count: int
    medium_count: int
    low_count: int
    info_count: int
    mitigated_count: int
    average_risk_score: float
    total_assets_affected: int
    top_risk_items: list[dict[str, Any]] = field(default_factory=list)


class AttackSurfaceRepositoryPort(ABC):
    @abstractmethod
    def save(self, exposure: Exposure) -> None:
        ...

    @abstractmethod
    def get(self, exposure_id: str) -> Exposure:
        ...

    @abstractmethod
    def delete(self, exposure_id: str) -> None:
        ...

    @abstractmethod
    def fetch_all(
        self,
        filter_: ExposureFilter | None = None,
        *,
        limit: int = 50,
        offset: int = 0,
    ) -> list[Exposure]:
        ...

    @abstractmethod
    def count(self, filter_: ExposureFilter | None = None) -> int:
        ...

    @abstractmethod
    def summary(self) -> AttackSurfaceSummary:
        ...

    @abstractmethod
    def get_by_asset(self, asset_id: str, *, limit: int = 50, offset: int = 0) -> list[Exposure]:
        ...

    @abstractmethod
    def count_by_asset(self, asset_id: str) -> int:
        ...

    @abstractmethod
    def get_by_type(self, exposure_type: ExposureType) -> list[Exposure]:
        ...

    @abstractmethod
    def get_high_risk(self, min_score: float = 50.0) -> list[Exposure]:
        ...

    @abstractmethod
    def search(self, query: str, *, limit: int = 20) -> list[Exposure]:
        ...

    @abstractmethod
    def save_history(self, entry: ExposureHistoryEntry) -> None:
        ...

    @abstractmethod
    def get_history(self, exposure_id: str, *, limit: int = 50) -> list[ExposureHistoryEntry]:
        ...

    @abstractmethod
    def get_trend_data(self, days: int = 30) -> list[dict[str, Any]]:
        ...

    @abstractmethod
    def mark_mitigated(self, exposure_id: str) -> None:
        ...

    @abstractmethod
    def get_assets_with_exposures(self) -> list[str]:
        ...
