from __future__ import annotations

from abc import ABC, abstractmethod
from dataclasses import dataclass
from typing import Any, Protocol

from kingsec.domain.monitoring import (
    Alert,
    AlertSeverity,
    AlertStatus,
    MonitorEvent,
    MonitorEventType,
    MonitoringDashboardSummary,
    MonitoringStatus,
    Rule,
)


@dataclass(frozen=True)
class MonitorEventFilter:
    event_type: MonitorEventType | None = None
    asset_id: str | None = None
    severity: AlertSeverity | None = None
    source: str | None = None
    search: str | None = None
    created_after: str | None = None
    created_before: str | None = None


@dataclass(frozen=True)
class AlertFilter:
    rule_id: str | None = None
    severity: AlertSeverity | None = None
    status: AlertStatus | None = None
    asset_id: str | None = None
    search: str | None = None
    created_after: str | None = None
    created_before: str | None = None


@dataclass(frozen=True)
class RuleFilter:
    enabled: bool | None = None
    event_type: MonitorEventType | None = None
    search: str | None = None


@dataclass(frozen=True)
class MonitoringTrendPoint:
    date: str
    events_count: int
    alerts_count: int
    critical_alerts: int
    high_alerts: int


@dataclass(frozen=True)
class AssetHealthSnapshot:
    asset_id: str
    status: MonitoringStatus
    risk_score: float
    exposure_count: int
    finding_count: int
    last_seen: str | None


@dataclass(frozen=True)
class MonitoringSummaryStats:
    events_last_24h: int = 0
    events_last_7d: int = 0
    alerts_last_24h: int = 0
    alerts_open: int = 0
    alerts_critical: int = 0
    alerts_high: int = 0
    rules_active: int = 0
    rules_total: int = 0
    assets_monitored: int = 0
    assets_healthy: int = 0
    assets_warning: int = 0
    assets_critical: int = 0
    total_changes_detected: int = 0


class MonitoringEventRepositoryPort(ABC):
    @abstractmethod
    def save_event(self, event: MonitorEvent) -> None:
        ...

    @abstractmethod
    def get_event(self, event_id: str) -> MonitorEvent:
        ...

    @abstractmethod
    def fetch_events(
        self,
        filter_: MonitorEventFilter | None = None,
        *,
        limit: int = 50,
        offset: int = 0,
    ) -> list[MonitorEvent]:
        ...

    @abstractmethod
    def count_events(self, filter_: MonitorEventFilter | None = None) -> int:
        ...

    @abstractmethod
    def get_event_trend(self, days: int = 30) -> list[MonitoringTrendPoint]:
        ...


class AlertRepositoryPort(ABC):
    @abstractmethod
    def save_alert(self, alert: Alert) -> None:
        ...

    @abstractmethod
    def get_alert(self, alert_id: str) -> Alert:
        ...

    @abstractmethod
    def fetch_alerts(
        self,
        filter_: AlertFilter | None = None,
        *,
        limit: int = 50,
        offset: int = 0,
    ) -> list[Alert]:
        ...

    @abstractmethod
    def count_alerts(self, filter_: AlertFilter | None = None) -> int:
        ...

    @abstractmethod
    def get_open_alerts_count(self) -> int:
        ...

    @abstractmethod
    def get_critical_alerts_count(self) -> int:
        ...

    @abstractmethod
    def get_alert_trend(self, days: int = 30) -> list[MonitoringTrendPoint]:
        ...


class RuleRepositoryPort(ABC):
    @abstractmethod
    def save_rule(self, rule: Rule) -> None:
        ...

    @abstractmethod
    def get_rule(self, rule_id: str) -> Rule:
        ...

    @abstractmethod
    def delete_rule(self, rule_id: str) -> None:
        ...

    @abstractmethod
    def fetch_rules(
        self,
        filter_: RuleFilter | None = None,
        *,
        limit: int = 100,
        offset: int = 0,
    ) -> list[Rule]:
        ...

    @abstractmethod
    def count_rules(self, filter_: RuleFilter | None = None) -> int:
        ...

    @abstractmethod
    def get_enabled_rules(self) -> list[Rule]:
        ...


class MonitoringDashboardRepositoryPort(ABC):
    @abstractmethod
    def get_dashboard_summary(self) -> MonitoringDashboardSummary:
        ...

    @abstractmethod
    def get_asset_health_snapshots(self) -> list[AssetHealthSnapshot]:
        ...

    @abstractmethod
    def get_summary_stats(self) -> MonitoringSummaryStats:
        ...

    @abstractmethod
    def get_exposure_trend(self, days: int = 30) -> list[dict[str, Any]]:
        ...

    @abstractmethod
    def get_compliance_trend(self, days: int = 30) -> list[dict[str, Any]]:
        ...

    @abstractmethod
    def get_risk_trend(self, days: int = 30) -> list[dict[str, Any]]:
        ...


class NotificationSenderPort(Protocol):
    def send_notification(
        self,
        channel: str,
        title: str,
        message: str,
        *,
        severity: str = "medium",
        metadata: dict[str, Any] | None = None,
    ) -> None:
        ...


class AuditPublisherPort(Protocol):
    def publish(
        self,
        action: str,
        resource_type: str,
        resource_id: str,
        *,
        metadata: dict[str, Any] | None = None,
    ) -> None:
        ...
