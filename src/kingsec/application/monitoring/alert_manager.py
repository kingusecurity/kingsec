from __future__ import annotations

from datetime import UTC, datetime
from typing import Any

from kingsec.domain.monitoring import Alert, AlertStatus

from .ports import AlertFilter, AlertRepositoryPort, AuditPublisherPort, NotificationSenderPort


class AlertManager:
    def __init__(
        self,
        alert_repo: AlertRepositoryPort,
        notification_sender: NotificationSenderPort | None = None,
        audit_publisher: AuditPublisherPort | None = None,
    ) -> None:
        self._repo = alert_repo
        self._notifier = notification_sender
        self._audit = audit_publisher

    def create_alert(self, alert: Alert) -> Alert:
        self._repo.save_alert(alert)
        self._send_notifications(alert)
        self._audit_event("alert_created", str(alert.id), {"rule_id": alert.rule_id, "severity": alert.severity.value})
        return alert

    def get_alert(self, alert_id: str) -> Alert:
        return self._repo.get_alert(alert_id)

    def list_alerts(
        self,
        filter_: AlertFilter | None = None,
        *,
        limit: int = 50,
        offset: int = 0,
    ) -> list[Alert]:
        return self._repo.fetch_alerts(filter_, limit=limit, offset=offset)

    def count_alerts(self, filter_: AlertFilter | None = None) -> int:
        return self._repo.count_alerts(filter_)

    def acknowledge_alert(self, alert_id: str, by: str = "system") -> Alert:
        alert = self._repo.get_alert(alert_id)
        alert.acknowledge(by=by)
        self._repo.save_alert(alert)
        self._audit_event("alert_acknowledged", alert_id, {"by": by})
        return alert

    def resolve_alert(self, alert_id: str, by: str = "system") -> Alert:
        alert = self._repo.get_alert(alert_id)
        alert.resolve(by=by)
        self._repo.save_alert(alert)
        self._audit_event("alert_resolved", alert_id, {"by": by})
        return alert

    def dismiss_alert(self, alert_id: str) -> Alert:
        alert = self._repo.get_alert(alert_id)
        alert.dismiss()
        self._repo.save_alert(alert)
        self._audit_event("alert_dismissed", alert_id, {})
        return alert

    def get_open_alert_count(self) -> int:
        return self._repo.get_open_alerts_count()

    def get_critical_alert_count(self) -> int:
        return self._repo.get_critical_alerts_count()

    def _send_notifications(self, alert: Alert) -> None:
        if self._notifier is None:
            return
        self._notifier.send_notification(
            channel="in_app",
            title=alert.title,
            message=alert.description,
            severity=alert.severity.value,
            metadata={
                "alert_id": str(alert.id),
                "rule_id": alert.rule_id,
                "asset_id": alert.asset_id,
            },
        )

    def _audit_event(self, action: str, resource_id: str, metadata: dict[str, Any]) -> None:
        if self._audit is None:
            return
        self._audit.publish(
            action=action,
            resource_type="alert",
            resource_id=resource_id,
            metadata=metadata,
        )
