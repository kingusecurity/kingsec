from __future__ import annotations

from datetime import UTC, datetime
from typing import Any

from kingsec.application.monitoring.alert_manager import AlertManager
from kingsec.application.monitoring.detectors import AssetChangeDetector, FindingChangeDetector
from kingsec.application.monitoring.ports import (
    AlertFilter,
    AuditPublisherPort,
    MonitorEventFilter,
    MonitoringEventRepositoryPort,
    RuleFilter,
    RuleRepositoryPort,
)
from kingsec.application.monitoring.rules import MonitoringRuleEngine
from kingsec.domain.monitoring import (
    Alert,
    MonitorEvent,
    Rule,
    RuleCondition,
)


class MonitoringService:
    def __init__(
        self,
        event_repo: MonitoringEventRepositoryPort,
        rule_repo: RuleRepositoryPort,
        alert_manager: AlertManager,
        rule_engine: MonitoringRuleEngine,
        asset_detector: AssetChangeDetector | None = None,
        finding_detector: FindingChangeDetector | None = None,
        audit_publisher: AuditPublisherPort | None = None,
    ) -> None:
        self._event_repo = event_repo
        self._rule_repo = rule_repo
        self._alert_manager = alert_manager
        self._rule_engine = rule_engine
        self._asset_detector = asset_detector or AssetChangeDetector()
        self._finding_detector = finding_detector or FindingChangeDetector()
        self._audit = audit_publisher

    # --- Events ---

    def record_event(self, event: MonitorEvent) -> MonitorEvent:
        self._event_repo.save_event(event)
        self._process_event_rules(event)
        self._audit_event("monitoring_event_recorded", str(event.id), {"event_type": event.event_type.value})
        return event

    def get_event(self, event_id: str) -> MonitorEvent:
        return self._event_repo.get_event(event_id)

    def list_events(
        self,
        filter_: MonitorEventFilter | None = None,
        *,
        limit: int = 50,
        offset: int = 0,
    ) -> list[MonitorEvent]:
        return self._event_repo.fetch_events(filter_, limit=limit, offset=offset)

    def count_events(self, filter_: MonitorEventFilter | None = None) -> int:
        return self._event_repo.count_events(filter_)

    # --- Rules ---

    def create_rule(
        self,
        name: str,
        *,
        description: str = "",
        event_type_str: str | None = None,
        conditions: list[dict[str, str]] | None = None,
        alert_severity: str = "medium",
        alert_title_template: str = "",
        alert_description_template: str = "",
        cooldown_minutes: int = 60,
        notify_channels: list[str] | None = None,
    ) -> Rule:
        from kingsec.domain.monitoring import AlertSeverity, MonitorEventType

        event_type = MonitorEventType(event_type_str) if event_type_str else None
        rule_conditions: list[RuleCondition] = []
        if conditions:
            for c in conditions:
                from kingsec.domain.monitoring import RuleConditionOperator
                rule_conditions.append(
                    RuleCondition(
                        field=c.get("field", ""),
                        operator=RuleConditionOperator(c.get("operator", "equals")),
                        value=c.get("value", ""),
                    )
                )
        rule = Rule.create(
            name,
            description=description,
            event_type=event_type,
            conditions=rule_conditions,
            alert_severity=AlertSeverity(alert_severity),
            alert_title_template=alert_title_template,
            alert_description_template=alert_description_template,
            cooldown_minutes=cooldown_minutes,
            notify_channels=notify_channels,
        )
        self._rule_repo.save_rule(rule)
        self._audit_event("monitoring_rule_created", str(rule.id), {"name": name})
        return rule

    def get_rule(self, rule_id: str) -> Rule:
        return self._rule_repo.get_rule(rule_id)

    def update_rule(self, rule_id: str, updates: dict[str, Any]) -> Rule:
        rule = self._rule_repo.get_rule(rule_id)
        for key, value in updates.items():
            private = f"_{key}"
            if hasattr(rule, private):
                setattr(rule, private, value)
        self._rule_repo.save_rule(rule)
        return rule

    def delete_rule(self, rule_id: str) -> None:
        self._rule_repo.get_rule(rule_id)
        self._rule_repo.delete_rule(rule_id)

    def list_rules(
        self,
        filter_: RuleFilter | None = None,
        *,
        limit: int = 100,
        offset: int = 0,
    ) -> list[Rule]:
        return self._rule_repo.fetch_rules(filter_, limit=limit, offset=offset)

    def count_rules(self, filter_: RuleFilter | None = None) -> int:
        return self._rule_repo.count_rules(filter_)

    def enable_rule(self, rule_id: str) -> Rule:
        rule = self._rule_repo.get_rule(rule_id)
        rule.enable()
        self._rule_repo.save_rule(rule)
        return rule

    def disable_rule(self, rule_id: str) -> Rule:
        rule = self._rule_repo.get_rule(rule_id)
        rule.disable()
        self._rule_repo.save_rule(rule)
        return rule

    def seed_default_rules(self) -> list[Rule]:
        existing = self._rule_repo.count_rules()
        if existing > 0:
            return self._rule_repo.fetch_rules()
        rules = self._rule_engine.get_default_rules()
        for r in rules:
            self._rule_repo.save_rule(r)
        return rules

    # --- Alerts ---

    def list_alerts(
        self,
        filter_: AlertFilter | None = None,
        *,
        limit: int = 50,
        offset: int = 0,
    ) -> list[Alert]:
        return self._alert_manager.list_alerts(filter_, limit=limit, offset=offset)

    def count_alerts(self, filter_: AlertFilter | None = None) -> int:
        return self._alert_manager.count_alerts(filter_)

    def get_alert(self, alert_id: str) -> Alert:
        return self._alert_manager.get_alert(alert_id)

    def acknowledge_alert(self, alert_id: str, by: str = "user") -> Alert:
        return self._alert_manager.acknowledge_alert(alert_id, by=by)

    def resolve_alert(self, alert_id: str, by: str = "user") -> Alert:
        return self._alert_manager.resolve_alert(alert_id, by=by)

    def dismiss_alert(self, alert_id: str) -> Alert:
        return self._alert_manager.dismiss_alert(alert_id)

    # --- Rule processing ---

    def _process_event_rules(self, event: MonitorEvent) -> None:
        rules = self._rule_repo.get_enabled_rules()
        recent_alerts = self._alert_manager.list_alerts(
            AlertFilter(created_after=datetime.now(UTC).isoformat()),
            limit=100,
        )
        matching = self._rule_engine.evaluate(event, rules, recent_alerts=recent_alerts)
        for rule in matching:
            alert = self._rule_engine.generate_alert(rule, event)
            self._alert_manager.create_alert(alert)

    # --- Audit ---

    def _audit_event(self, action: str, resource_id: str, metadata: dict[str, Any]) -> None:
        if self._audit is None:
            return
        self._audit.publish(
            action=action,
            resource_type="monitoring",
            resource_id=resource_id,
            metadata=metadata,
        )
