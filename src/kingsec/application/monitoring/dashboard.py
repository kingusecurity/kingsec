from __future__ import annotations

from typing import Any

from kingsec.domain.monitoring import MonitoringDashboardSummary, MonitoringStatus

from .ports import (
    AlertRepositoryPort,
    AssetHealthSnapshot,
    MonitoringDashboardRepositoryPort,
    MonitoringEventRepositoryPort,
    MonitoringSummaryStats,
    MonitoringTrendPoint,
    RuleRepositoryPort,
)


class MonitoringDashboardService:
    def __init__(
        self,
        dashboard_repo: MonitoringDashboardRepositoryPort,
        event_repo: MonitoringEventRepositoryPort,
        alert_repo: AlertRepositoryPort,
        rule_repo: RuleRepositoryPort,
    ) -> None:
        self._dashboard_repo = dashboard_repo
        self._event_repo = event_repo
        self._alert_repo = alert_repo
        self._rule_repo = rule_repo

    def get_summary(self) -> MonitoringDashboardSummary:
        return self._dashboard_repo.get_dashboard_summary()

    def get_summary_stats(self) -> MonitoringSummaryStats:
        return self._dashboard_repo.get_summary_stats()

    def get_asset_health(self) -> list[AssetHealthSnapshot]:
        return self._dashboard_repo.get_asset_health_snapshots()

    def get_event_trend(self, days: int = 30) -> list[MonitoringTrendPoint]:
        return self._event_repo.get_event_trend(days=days)

    def get_alert_trend(self, days: int = 30) -> list[MonitoringTrendPoint]:
        return self._alert_repo.get_alert_trend(days=days)

    def get_exposure_trend(self, days: int = 30) -> list[dict[str, Any]]:
        return self._dashboard_repo.get_exposure_trend(days=days)

    def get_compliance_trend(self, days: int = 30) -> list[dict[str, Any]]:
        return self._dashboard_repo.get_compliance_trend(days=days)

    def get_risk_trend(self, days: int = 30) -> list[dict[str, Any]]:
        return self._dashboard_repo.get_risk_trend(days=days)

    def get_health_status(self) -> MonitoringStatus:
        stats = self._dashboard_repo.get_summary_stats()
        if stats.assets_critical > 0:
            return MonitoringStatus.CRITICAL
        if stats.assets_warning > 0:
            return MonitoringStatus.WARNING
        return MonitoringStatus.HEALTHY
