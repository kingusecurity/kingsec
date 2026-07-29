from __future__ import annotations

from dataclasses import dataclass, field
from datetime import UTC, datetime
from enum import StrEnum
from typing import Any

from .errors import InvariantViolation
from .identifiers import AlertId, MonitorEventId, RuleId


class MonitorEventType(StrEnum):
    NEW_HOST = "new_host"
    HOST_DISAPPEARED = "host_disappeared"
    NEW_OPEN_PORT = "new_open_port"
    CLOSED_PORT = "closed_port"
    SERVICE_VERSION_CHANGED = "service_version_changed"
    TECHNOLOGY_CHANGED = "technology_changed"
    CERTIFICATE_EXPIRES_SOON = "certificate_expires_soon"
    CERTIFICATE_RENEWED = "certificate_renewed"
    TLS_DOWNGRADED = "tls_downgraded"
    NEW_CRITICAL_FINDING = "new_critical_finding"
    FINDING_RESOLVED = "finding_resolved"
    COMPLIANCE_SCORE_CHANGED = "compliance_score_changed"
    EXPOSURE_SCORE_CHANGED = "exposure_score_changed"
    RISK_SCORE_CHANGED = "risk_score_changed"
    ASSET_CREATED = "asset_created"
    ASSET_UPDATED = "asset_updated"


class AlertSeverity(StrEnum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"


class AlertStatus(StrEnum):
    OPEN = "open"
    ACKNOWLEDGED = "acknowledged"
    RESOLVED = "resolved"
    DISMISSED = "dismissed"


class RuleConditionOperator(StrEnum):
    EQUALS = "equals"
    NOT_EQUALS = "not_equals"
    GREATER_THAN = "greater_than"
    LESS_THAN = "less_than"
    CONTAINS = "contains"
    CHANGED = "changed"
    INCREASED = "increased"
    DECREASED = "decreased"


class MonitoringStatus(StrEnum):
    HEALTHY = "healthy"
    WARNING = "warning"
    CRITICAL = "critical"
    UNKNOWN = "unknown"


EVENT_SEVERITY_MAP: dict[MonitorEventType, AlertSeverity] = {
    MonitorEventType.NEW_HOST: AlertSeverity.LOW,
    MonitorEventType.HOST_DISAPPEARED: AlertSeverity.MEDIUM,
    MonitorEventType.NEW_OPEN_PORT: AlertSeverity.MEDIUM,
    MonitorEventType.CLOSED_PORT: AlertSeverity.LOW,
    MonitorEventType.SERVICE_VERSION_CHANGED: AlertSeverity.LOW,
    MonitorEventType.TECHNOLOGY_CHANGED: AlertSeverity.LOW,
    MonitorEventType.CERTIFICATE_EXPIRES_SOON: AlertSeverity.HIGH,
    MonitorEventType.CERTIFICATE_RENEWED: AlertSeverity.INFO,
    MonitorEventType.TLS_DOWNGRADED: AlertSeverity.CRITICAL,
    MonitorEventType.NEW_CRITICAL_FINDING: AlertSeverity.CRITICAL,
    MonitorEventType.FINDING_RESOLVED: AlertSeverity.INFO,
    MonitorEventType.COMPLIANCE_SCORE_CHANGED: AlertSeverity.HIGH,
    MonitorEventType.EXPOSURE_SCORE_CHANGED: AlertSeverity.MEDIUM,
    MonitorEventType.RISK_SCORE_CHANGED: AlertSeverity.HIGH,
    MonitorEventType.ASSET_CREATED: AlertSeverity.LOW,
    MonitorEventType.ASSET_UPDATED: AlertSeverity.INFO,
}


@dataclass(frozen=True, slots=True)
class MonitorEventContext:
    key: str
    value: str
    previous_value: str | None = None
    metadata: dict[str, Any] = field(default_factory=dict)


class MonitorEvent:
    def __init__(
        self,
        event_id: MonitorEventId,
        event_type: MonitorEventType,
        *,
        asset_id: str | None = None,
        assessment_id: str | None = None,
        source: str = "monitor",
        title: str = "",
        description: str = "",
        context: list[MonitorEventContext] | None = None,
        severity: AlertSeverity | None = None,
        metadata: dict[str, Any] | None = None,
        timestamp: str | None = None,
    ) -> None:
        if not isinstance(event_id, MonitorEventId):
            raise InvariantViolation("event_id must be a MonitorEventId")
        now = timestamp or datetime.now(UTC).isoformat()
        self._id = event_id
        self._event_type = event_type
        self._asset_id = asset_id
        self._assessment_id = assessment_id
        self._source = source
        self._title = title
        self._description = description
        self._context = list(context) if context else []
        self._severity = severity or EVENT_SEVERITY_MAP.get(event_type, AlertSeverity.INFO)
        self._metadata = dict(metadata) if metadata else {}
        self._timestamp = now

    @classmethod
    def create(
        cls,
        event_type: MonitorEventType,
        *,
        asset_id: str | None = None,
        assessment_id: str | None = None,
        title: str = "",
        description: str = "",
        **kwargs: Any,
    ) -> MonitorEvent:
        return cls(
            MonitorEventId.generate(),
            event_type,
            asset_id=asset_id,
            assessment_id=assessment_id,
            title=title or event_type.value.replace("_", " ").title(),
            description=description,
            **kwargs,
        )

    @property
    def id(self) -> MonitorEventId:
        return self._id

    @property
    def event_type(self) -> MonitorEventType:
        return self._event_type

    @property
    def asset_id(self) -> str | None:
        return self._asset_id

    @property
    def assessment_id(self) -> str | None:
        return self._assessment_id

    @property
    def source(self) -> str:
        return self._source

    @property
    def title(self) -> str:
        return self._title

    @property
    def description(self) -> str:
        return self._description

    @property
    def context(self) -> tuple[MonitorEventContext, ...]:
        return tuple(self._context)

    @property
    def severity(self) -> AlertSeverity:
        return self._severity

    @property
    def metadata(self) -> dict[str, Any]:
        return dict(self._metadata)

    @property
    def timestamp(self) -> str:
        return self._timestamp

    def __eq__(self, other: object) -> bool:
        return isinstance(other, MonitorEvent) and other._id == self._id

    def __hash__(self) -> int:
        return hash(self._id)

    def __repr__(self) -> str:
        return f"MonitorEvent(id={self._id.value!r}, type={self._event_type.value})"


class Alert:
    def __init__(
        self,
        alert_id: AlertId,
        rule_id: str,
        *,
        title: str = "",
        description: str = "",
        severity: AlertSeverity = AlertSeverity.MEDIUM,
        status: AlertStatus = AlertStatus.OPEN,
        source_event_id: str | None = None,
        asset_id: str | None = None,
        assessment_id: str | None = None,
        metadata: dict[str, Any] | None = None,
        created_at: str | None = None,
        acknowledged_at: str | None = None,
        resolved_at: str | None = None,
        acknowledged_by: str | None = None,
        resolved_by: str | None = None,
    ) -> None:
        if not isinstance(alert_id, AlertId):
            raise InvariantViolation("alert_id must be an AlertId")
        now = created_at or datetime.now(UTC).isoformat()
        self._id = alert_id
        self._rule_id = rule_id
        self._title = title
        self._description = description
        self._severity = severity
        self._status = status
        self._source_event_id = source_event_id
        self._asset_id = asset_id
        self._assessment_id = assessment_id
        self._metadata = dict(metadata) if metadata else {}
        self._created_at = now
        self._acknowledged_at = acknowledged_at
        self._resolved_at = resolved_at
        self._acknowledged_by = acknowledged_by
        self._resolved_by = resolved_by

    @classmethod
    def create(
        cls,
        rule_id: str,
        *,
        title: str = "",
        description: str = "",
        severity: AlertSeverity = AlertSeverity.MEDIUM,
        source_event_id: str | None = None,
        asset_id: str | None = None,
        **kwargs: Any,
    ) -> Alert:
        return cls(
            AlertId.generate(),
            rule_id,
            title=title,
            description=description,
            severity=severity,
            source_event_id=source_event_id,
            asset_id=asset_id,
            **kwargs,
        )

    @property
    def id(self) -> AlertId:
        return self._id

    @property
    def rule_id(self) -> str:
        return self._rule_id

    @property
    def title(self) -> str:
        return self._title

    @property
    def description(self) -> str:
        return self._description

    @property
    def severity(self) -> AlertSeverity:
        return self._severity

    @property
    def status(self) -> AlertStatus:
        return self._status

    @property
    def source_event_id(self) -> str | None:
        return self._source_event_id

    @property
    def asset_id(self) -> str | None:
        return self._asset_id

    @property
    def assessment_id(self) -> str | None:
        return self._assessment_id

    @property
    def metadata(self) -> dict[str, Any]:
        return dict(self._metadata)

    @property
    def created_at(self) -> str:
        return self._created_at

    @property
    def acknowledged_at(self) -> str | None:
        return self._acknowledged_at

    @property
    def resolved_at(self) -> str | None:
        return self._resolved_at

    @property
    def acknowledged_by(self) -> str | None:
        return self._acknowledged_by

    @property
    def resolved_by(self) -> str | None:
        return self._resolved_by

    def acknowledge(self, by: str = "system") -> None:
        self._status = AlertStatus.ACKNOWLEDGED
        self._acknowledged_at = datetime.now(UTC).isoformat()
        self._acknowledged_by = by

    def resolve(self, by: str = "system") -> None:
        self._status = AlertStatus.RESOLVED
        self._resolved_at = datetime.now(UTC).isoformat()
        self._resolved_by = by

    def dismiss(self) -> None:
        self._status = AlertStatus.DISMISSED

    def __eq__(self, other: object) -> bool:
        return isinstance(other, Alert) and other._id == self._id

    def __hash__(self) -> int:
        return hash(self._id)

    def __repr__(self) -> str:
        return f"Alert(id={self._id.value!r}, rule={self._rule_id!r}, severity={self._severity.value})"


@dataclass(frozen=True, slots=True)
class RuleCondition:
    field: str
    operator: RuleConditionOperator
    value: str

    def evaluate(self, event: MonitorEvent) -> bool:
        event_value = _get_event_attr(event, self.field)
        if event_value is None:
            return False
        if self.operator == RuleConditionOperator.EQUALS:
            return str(event_value) == self.value
        if self.operator == RuleConditionOperator.NOT_EQUALS:
            return str(event_value) != self.value
        if self.operator in (RuleConditionOperator.GREATER_THAN, RuleConditionOperator.LESS_THAN):
            try:
                val = float(event_value)
                threshold = float(self.value)
                return val > threshold if self.operator == RuleConditionOperator.GREATER_THAN else val < threshold
            except (ValueError, TypeError):
                return False
        if self.operator == RuleConditionOperator.CONTAINS:
            return self.value.lower() in str(event_value).lower()
        return True


class Rule:
    def __init__(
        self,
        rule_id: RuleId,
        name: str,
        *,
        description: str = "",
        event_type: MonitorEventType | None = None,
        conditions: list[RuleCondition] | None = None,
        alert_severity: AlertSeverity = AlertSeverity.MEDIUM,
        alert_title_template: str = "",
        alert_description_template: str = "",
        enabled: bool = True,
        cooldown_minutes: int = 60,
        notify_channels: list[str] | None = None,
        metadata: dict[str, Any] | None = None,
        created_at: str | None = None,
        updated_at: str | None = None,
    ) -> None:
        if not isinstance(rule_id, RuleId):
            raise InvariantViolation("rule_id must be a RuleId")
        now = created_at or datetime.now(UTC).isoformat()
        self._id = rule_id
        self._name = name
        self._description = description
        self._event_type = event_type
        self._conditions = list(conditions) if conditions else []
        self._alert_severity = alert_severity
        self._alert_title_template = alert_title_template or f"Rule triggered: {name}"
        self._alert_description_template = alert_description_template
        self._enabled = enabled
        self._cooldown_minutes = cooldown_minutes
        self._notify_channels = notify_channels or []
        self._metadata = dict(metadata) if metadata else {}
        self._created_at = now
        self._updated_at = updated_at or now

    @classmethod
    def create(
        cls,
        name: str,
        *,
        event_type: MonitorEventType | None = None,
        conditions: list[RuleCondition] | None = None,
        alert_severity: AlertSeverity = AlertSeverity.MEDIUM,
        **kwargs: Any,
    ) -> Rule:
        return cls(
            RuleId.generate(),
            name,
            event_type=event_type,
            conditions=conditions,
            alert_severity=alert_severity,
            **kwargs,
        )

    @property
    def id(self) -> RuleId:
        return self._id

    @property
    def name(self) -> str:
        return self._name

    @property
    def description(self) -> str:
        return self._description

    @property
    def event_type(self) -> MonitorEventType | None:
        return self._event_type

    @property
    def conditions(self) -> tuple[RuleCondition, ...]:
        return tuple(self._conditions)

    @property
    def alert_severity(self) -> AlertSeverity:
        return self._alert_severity

    @property
    def alert_title_template(self) -> str:
        return self._alert_title_template

    @property
    def alert_description_template(self) -> str:
        return self._alert_description_template

    @property
    def enabled(self) -> bool:
        return self._enabled

    @property
    def cooldown_minutes(self) -> int:
        return self._cooldown_minutes

    @property
    def notify_channels(self) -> tuple[str, ...]:
        return tuple(self._notify_channels)

    @property
    def metadata(self) -> dict[str, Any]:
        return dict(self._metadata)

    @property
    def created_at(self) -> str:
        return self._created_at

    @property
    def updated_at(self) -> str:
        return self._updated_at

    def matches(self, event: MonitorEvent) -> bool:
        if self._event_type is not None and event.event_type != self._event_type:
            return False
        if not self._conditions:
            return self._event_type is not None and event.event_type == self._event_type
        return all(c.evaluate(event) for c in self._conditions)

    def enable(self) -> None:
        self._enabled = True
        self._updated_at = datetime.now(UTC).isoformat()

    def disable(self) -> None:
        self._enabled = False
        self._updated_at = datetime.now(UTC).isoformat()

    def __eq__(self, other: object) -> bool:
        return isinstance(other, Rule) and other._id == self._id

    def __hash__(self) -> int:
        return hash(self._id)

    def __repr__(self) -> str:
        return f"Rule(id={self._id.value!r}, name={self._name!r})"


@dataclass(frozen=True, slots=True)
class MonitoringDashboardSummary:
    total_events_24h: int = 0
    total_alerts_open: int = 0
    total_alerts_critical: int = 0
    total_alerts_high: int = 0
    total_rules_active: int = 0
    asset_health_percentage: float = 100.0
    last_scan_time: str | None = None
    exposure_trend: str = "stable"
    risk_trend: str = "stable"
    compliance_trend: str = "stable"
    upcoming_certificate_expirations: int = 0
    assets_monitored: int = 0
    recent_events: list[dict[str, Any]] = field(default_factory=list)
    recent_alerts: list[dict[str, Any]] = field(default_factory=list)


def _get_event_attr(event: MonitorEvent, name: str) -> Any:
    mapping = {
        "type": "event_type",
        "event_type": "event_type",
        "severity": "severity",
        "source": "source",
        "asset_id": "asset_id",
        "assessment_id": "assessment_id",
    }
    attr = mapping.get(name, name)
    return getattr(event, attr, None)
