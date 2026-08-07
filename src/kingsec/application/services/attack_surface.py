from __future__ import annotations

from datetime import UTC, datetime
from typing import Any

from kingsec.application.errors import ExposureNotFoundError
from kingsec.application.ports.attack_surface import (
    AttackSurfaceRepositoryPort,
    AttackSurfaceSummary,
    ExposureFilter,
)
from kingsec.domain.attack_surface import (
    Exposure,
    ExposureHistoryEntry,
    ExposureRisk,
    ExposureSeverity,
    ExposureStatus,
    ExposureType,
)


class AttackSurfaceService:
    def __init__(self, repo: AttackSurfaceRepositoryPort) -> None:
        self._repo = repo

    # --- CRUD ---

    def record_exposure(
        self,
        asset_id: str,
        exposure_type: ExposureType,
        *,
        severity: ExposureSeverity | None = None,
        title: str = "",
        description: str = "",
        **kwargs: Any,
    ) -> Exposure:
        exposure = Exposure.create(
            asset_id,
            exposure_type,
            severity=severity,
            title=title,
            description=description,
            **kwargs,
        )
        exposure.calculate_risk_score()
        self._repo.save(exposure)
        self._repo.save_history(
            ExposureHistoryEntry(
                exposure_id=str(exposure.id),
                event_type="created",
                description=f"Exposure recorded: {exposure.title}",
                timestamp=datetime.now(UTC).isoformat(),
            )
        )
        return exposure

    def get_exposure(self, exposure_id: str) -> Exposure:
        try:
            return self._repo.get(exposure_id)
        except ExposureNotFoundError:
            raise ExposureNotFoundError(f"Exposure not found: {exposure_id}") from None

    def delete_exposure(self, exposure_id: str) -> None:
        self._repo.get(exposure_id)
        self._repo.delete(exposure_id)

    def update_exposure(self, exposure_id: str, updates: dict[str, Any]) -> Exposure:
        exposure = self._repo.get(exposure_id)
        for key, value in updates.items():
            if hasattr(exposure, key):
                private = f"_{key}"
                if hasattr(exposure, private):
                    setattr(exposure, private, value)
        exposure.calculate_risk_score()
        self._repo.save(exposure)
        return exposure

    # --- Listing & search ---

    def list_exposures(
        self,
        filter_: ExposureFilter | None = None,
        *,
        limit: int = 50,
        offset: int = 0,
    ) -> list[Exposure]:
        return self._repo.fetch_all(filter_, limit=limit, offset=offset)

    def count_exposures(self, filter_: ExposureFilter | None = None) -> int:
        return self._repo.count(filter_)

    def search_exposures(self, query: str, *, limit: int = 20) -> list[Exposure]:
        return self._repo.search(query, limit=limit)

    def get_summary(self) -> AttackSurfaceSummary:
        return self._repo.summary()

    # --- Asset exposures ---

    def get_asset_exposures(
        self,
        asset_id: str,
        *,
        limit: int = 50,
        offset: int = 0,
    ) -> list[Exposure]:
        return self._repo.get_by_asset(asset_id, limit=limit, offset=offset)

    def count_asset_exposures(self, asset_id: str) -> int:
        return self._repo.count_by_asset(asset_id)

    # --- Risk & mitigation ---

    def get_high_risk_exposures(self, min_score: float = 50.0) -> list[Exposure]:
        return self._repo.get_high_risk(min_score=min_score)

    def mitigate_exposure(self, exposure_id: str) -> Exposure:
        exposure = self._repo.get(exposure_id)
        exposure.update_status(ExposureStatus.MITIGATED)
        exposure.calculate_risk_score()
        self._repo.save(exposure)
        self._repo.save_history(
            ExposureHistoryEntry(
                exposure_id=exposure_id,
                event_type="mitigated",
                description=f"Exposure mitigated: {exposure.title}",
                timestamp=datetime.now(UTC).isoformat(),
            )
        )
        return exposure

    def update_exposure_remediation(self, exposure_id: str, remediation: str) -> Exposure:
        exposure = self._repo.get(exposure_id)
        exposure.update_remediation(remediation)
        self._repo.save(exposure)
        return exposure

    # --- History ---

    def get_exposure_history(self, exposure_id: str, *, limit: int = 50) -> list[ExposureHistoryEntry]:
        return self._repo.get_history(exposure_id, limit=limit)

    # --- Trend & analysis ---

    def get_exposure_trend(self, days: int = 30) -> list[dict[str, Any]]:
        return self._repo.get_trend_data(days=days)

    def get_exposure_risk(self) -> ExposureRisk:
        summary = self._repo.summary()
        total = summary.total_exposures or 1
        score = (
            summary.critical_count * 10.0
            + summary.high_count * 7.0
            + summary.medium_count * 4.0
            + summary.low_count * 2.0
            + summary.info_count * 0.5
        )
        normalized = min((score / total) * 10.0, 100.0)
        return ExposureRisk(
            exposure_score=round(normalized, 2),
            internet_exposure=round(
                (summary.by_source.get("internet", 0) / total) * 100.0, 2
            ),
            critical_asset_exposure=round(
                (summary.by_severity.get("critical", 0) / total) * 100.0, 2
            ),
            public_service_count=summary.by_type.get("public_service", 0),
            tls_score=100.0 - (summary.by_type.get("weak_tls_version", 0) * 10.0),
            trend="stable",
        )

    def get_assets_with_exposures(self) -> list[str]:
        return self._repo.get_assets_with_exposures()
