from __future__ import annotations

from datetime import UTC, datetime, timedelta
from typing import Any

from kingsec.domain.monitoring import (
    Alert,
    AlertSeverity,
    MonitorEvent,
    MonitorEventType,
    Rule,
    RuleCondition,
    RuleConditionOperator,
)


PREDEFINED_RULES: list[dict[str, Any]] = [
    {
        "name": "Critical Finding Detected",
        "description": "Triggers when a new critical severity finding appears",
        "event_type": MonitorEventType.NEW_CRITICAL_FINDING,
        "alert_severity": AlertSeverity.CRITICAL,
        "cooldown_minutes": 30,
        "notify_channels": ["email", "slack", "teams"],
    },
    {
        "name": "Exposure Score Increased",
        "description": "Triggers when the exposure score increases significantly",
        "event_type": MonitorEventType.EXPOSURE_SCORE_CHANGED,
        "conditions": [RuleCondition(field="severity", operator=RuleConditionOperator.EQUALS, value="critical")],
        "alert_severity": AlertSeverity.HIGH,
        "cooldown_minutes": 60,
        "notify_channels": ["email", "slack"],
    },
    {
        "name": "Certificate Expiring Soon",
        "description": "Triggers when a certificate expires within 14 days",
        "event_type": MonitorEventType.CERTIFICATE_EXPIRES_SOON,
        "alert_severity": AlertSeverity.HIGH,
        "cooldown_minutes": 1440,
        "notify_channels": ["email", "slack", "teams"],
    },
    {
        "name": "Risk Score Exceeded",
        "description": "Triggers when asset risk score exceeds 80",
        "event_type": MonitorEventType.RISK_SCORE_CHANGED,
        "alert_severity": AlertSeverity.CRITICAL,
        "cooldown_minutes": 60,
        "notify_channels": ["email", "slack"],
    },
    {
        "name": "Compliance Score Dropped",
        "description": "Triggers when compliance score decreases",
        "event_type": MonitorEventType.COMPLIANCE_SCORE_CHANGED,
        "alert_severity": AlertSeverity.HIGH,
        "cooldown_minutes": 1440,
        "notify_channels": ["email", "slack", "teams"],
    },
    {
        "name": "New Internet-Facing Asset",
        "description": "Triggers when a new host or internet-facing asset appears",
        "event_type": MonitorEventType.NEW_HOST,
        "alert_severity": AlertSeverity.MEDIUM,
        "cooldown_minutes": 60,
        "notify_channels": ["slack"],
    },
    {
        "name": "TLS Version Downgraded",
        "description": "Triggers when TLS version is downgraded",
        "event_type": MonitorEventType.TLS_DOWNGRADED,
        "alert_severity": AlertSeverity.CRITICAL,
        "cooldown_minutes": 30,
        "notify_channels": ["email", "slack", "teams"],
    },
    {
        "name": "New Open Port Detected",
        "description": "Triggers when a new open port is discovered on an asset",
        "event_type": MonitorEventType.NEW_OPEN_PORT,
        "alert_severity": AlertSeverity.MEDIUM,
        "cooldown_minutes": 120,
        "notify_channels": ["slack"],
    },
    {
        "name": "Host Disappeared",
        "description": "Triggers when a previously known host is no longer reachable",
        "event_type": MonitorEventType.HOST_DISAPPEARED,
        "alert_severity": AlertSeverity.HIGH,
        "cooldown_minutes": 1440,
        "notify_channels": ["email", "slack"],
    },
]


class MonitoringRuleEngine:
    def evaluate(
        self,
        event: MonitorEvent,
        rules: list[Rule],
        *,
        check_cooldown: bool = True,
        recent_alerts: list[Alert] | None = None,
    ) -> list[Rule]:
        matching: list[Rule] = []
        for rule in rules:
            if not rule.enabled:
                continue
            if not rule.matches(event):
                continue
            if check_cooldown and self._is_in_cooldown(rule, recent_alerts):
                continue
            matching.append(rule)
        return matching

    def _is_in_cooldown(self, rule: Rule, recent_alerts: list[Alert] | None = None) -> bool:
        if not recent_alerts:
            return False
        now = datetime.now(UTC)
        for alert in recent_alerts:
            if alert.rule_id != str(rule.id):
                continue
            if alert.status.value in ("dismissed", "resolved"):
                continue
            created = datetime.fromisoformat(alert.created_at)
            if (now - created).total_seconds() < rule.cooldown_minutes * 60:
                return True
        return False

    def generate_alert(self, rule: Rule, event: MonitorEvent) -> Alert:
        title = rule.alert_title_template.replace("{name}", rule.name).replace("{event_type}", event.event_type.value)
        description = rule.alert_description_template
        if not description:
            description = f"Rule '{rule.name}' triggered by {event.event_type.value} event: {event.title}"
        return Alert.create(
            rule_id=str(rule.id),
            title=title,
            description=description,
            severity=rule.alert_severity,
            source_event_id=str(event.id),
            asset_id=event.asset_id,
        )

    def get_default_rules(self) -> list[Rule]:
        return [Rule.create(**cfg) for cfg in PREDEFINED_RULES]
