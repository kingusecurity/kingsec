"""Tests for MonitoringService, focused on the create_rule/description fix."""

from __future__ import annotations

from kingsec.application.monitoring.alert_manager import AlertManager
from kingsec.application.monitoring.ports import (
    AlertFilter,
    AlertRepositoryPort,
    MonitorEventFilter,
    MonitoringEventRepositoryPort,
    MonitoringTrendPoint,
    RuleFilter,
    RuleRepositoryPort,
)
from kingsec.application.monitoring.rules import MonitoringRuleEngine
from kingsec.application.monitoring.service import MonitoringService
from kingsec.domain.monitoring import Alert, MonitorEvent, Rule


class InMemoryEventRepo(MonitoringEventRepositoryPort):
    def __init__(self) -> None:
        self._events: dict[str, MonitorEvent] = {}

    def save_event(self, event: MonitorEvent) -> None:
        self._events[str(event.id)] = event

    def get_event(self, event_id: str) -> MonitorEvent:
        return self._events[event_id]

    def fetch_events(
        self, filter_: MonitorEventFilter | None = None, *, limit: int = 50, offset: int = 0
    ) -> list[MonitorEvent]:
        return list(self._events.values())

    def count_events(self, filter_: MonitorEventFilter | None = None) -> int:
        return len(self._events)

    def get_event_trend(self, days: int = 30) -> list[MonitoringTrendPoint]:
        return []


class InMemoryRuleRepo(RuleRepositoryPort):
    def __init__(self) -> None:
        self._rules: dict[str, Rule] = {}

    def save_rule(self, rule: Rule) -> None:
        self._rules[str(rule.id)] = rule

    def get_rule(self, rule_id: str) -> Rule:
        return self._rules[rule_id]

    def delete_rule(self, rule_id: str) -> None:
        self._rules.pop(rule_id, None)

    def fetch_rules(
        self, filter_: RuleFilter | None = None, *, limit: int = 100, offset: int = 0
    ) -> list[Rule]:
        return list(self._rules.values())

    def count_rules(self, filter_: RuleFilter | None = None) -> int:
        return len(self._rules)

    def get_enabled_rules(self) -> list[Rule]:
        return [r for r in self._rules.values() if r.enabled]


class InMemoryAlertRepo(AlertRepositoryPort):
    def __init__(self) -> None:
        self._alerts: dict[str, Alert] = {}

    def save_alert(self, alert: Alert) -> None:
        self._alerts[str(alert.id)] = alert

    def get_alert(self, alert_id: str) -> Alert:
        return self._alerts[alert_id]

    def fetch_alerts(
        self, filter_: AlertFilter | None = None, *, limit: int = 50, offset: int = 0
    ) -> list[Alert]:
        return list(self._alerts.values())

    def count_alerts(self, filter_: AlertFilter | None = None) -> int:
        return len(self._alerts)

    def get_open_alerts_count(self) -> int:
        return len(self._alerts)

    def get_critical_alerts_count(self) -> int:
        return 0

    def get_alert_trend(self, days: int = 30) -> list[MonitoringTrendPoint]:
        return []


def make_service() -> MonitoringService:
    return MonitoringService(
        event_repo=InMemoryEventRepo(),
        rule_repo=InMemoryRuleRepo(),
        alert_manager=AlertManager(InMemoryAlertRepo()),
        rule_engine=MonitoringRuleEngine(),
    )


def test_create_rule_persists_description() -> None:
    service = make_service()

    rule = service.create_rule("High CVE Volume", description="Fires when CVE ingest spikes")

    assert rule.description == "Fires when CVE ingest spikes"
    stored = service.get_rule(str(rule.id))
    assert stored.description == "Fires when CVE ingest spikes"


def test_create_rule_defaults_description_to_empty_string() -> None:
    service = make_service()

    rule = service.create_rule("No Description Rule")

    assert rule.description == ""
