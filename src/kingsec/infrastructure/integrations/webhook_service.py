from __future__ import annotations

import hashlib
import hmac
import json
import time
import uuid
from datetime import UTC, datetime
from typing import Any

from kingsec.application.ports.outbound import AuditPublisher
from kingsec.domain.audit import AuditAction, AuditEntry
from kingsec.domain.integration import (
    DeliveryRecord,
    DeliveryStatus,
    IntegrationType,
    WebhookEventType,
)
from kingsec.infrastructure.config.models import IntegrationSettings
from kingsec.infrastructure.logging import get_logger
from kingsec.infrastructure.notifications.url_validator import SSRFError, validate_url

logger = get_logger("kingsec.infrastructure.integrations.webhook")

_RETRY_DELAYS = [10, 30, 60, 180, 300]
_MAX_ATTEMPTS = len(_RETRY_DELAYS) + 1


class WebhookDeliveryService:
    def __init__(
        self,
        settings: IntegrationSettings,
        audit: AuditPublisher,
    ) -> None:
        self._settings = settings
        self._audit = audit
        self._history: list[DeliveryRecord] = []

    def deliver(
        self,
        event_type: WebhookEventType,
        payload: dict[str, Any],
    ) -> list[DeliveryRecord]:
        records: list[DeliveryRecord] = []

        targets = self._get_targets(event_type)
        for integration_type, url in targets:
            record = self._attempt_delivery(integration_type, event_type, url, payload)
            records.append(record)
            self._history.append(record)
            self._audit_webhook(record)
        return records

    def _get_targets(self, event_type: WebhookEventType) -> list[tuple[IntegrationType, str]]:
        targets: list[tuple[IntegrationType, str]] = []
        if self._settings.generic_webhook_url:
            targets.append((IntegrationType.WEBHOOK, self._settings.generic_webhook_url))
        if self._settings.slack_webhook_url:
            targets.append((IntegrationType.SLACK, self._settings.slack_webhook_url))
        if self._settings.teams_webhook_url:
            targets.append((IntegrationType.MICROSOFT_TEAMS, self._settings.teams_webhook_url))
        if self._settings.discord_webhook_url:
            targets.append((IntegrationType.DISCORD, self._settings.discord_webhook_url))
        return targets

    def _attempt_delivery(
        self,
        integration_type: IntegrationType,
        event_type: WebhookEventType,
        url: str,
        payload: dict[str, Any],
    ) -> DeliveryRecord:
        from urllib.request import Request, urlopen

        record_id = str(uuid.uuid4())
        attempt = 1
        last_error: str | None = None

        while attempt <= _MAX_ATTEMPTS:
            try:
                validate_url(url)
                body = self._build_body(integration_type, event_type, payload)
                req = Request(url, data=body, method="POST")
                req.add_header("Content-Type", "application/json")
                if self._settings.webhook_secret:
                    sig = self._sign(body, self._settings.webhook_secret)
                    req.add_header("X-Signature-256", sig)
                with urlopen(req, timeout=15):
                    pass
                record = DeliveryRecord(
                    id=record_id,
                    integration_type=integration_type,
                    event_type=event_type.value,
                    status=DeliveryStatus.DELIVERED,
                    attempt=attempt,
                    max_attempts=_MAX_ATTEMPTS,
                    timestamp=datetime.now(UTC).isoformat(),
                )
                logger.info("Webhook delivered %s -> %s", event_type.value, integration_type.value)
                return record
            except SSRFError:
                last_error = "URL blocked by SSRF protection"
                logger.warning("SSRF block: %s", url)
                break
            except Exception as exc:
                last_error = str(exc)
                logger.warning("Webhook attempt %d/%d failed for %s: %s", attempt, _MAX_ATTEMPTS, integration_type.value, exc)
                if attempt < _MAX_ATTEMPTS:
                    delay = _RETRY_DELAYS[min(attempt - 1, len(_RETRY_DELAYS) - 1)]
                    time.sleep(delay)
                attempt += 1

        return DeliveryRecord(
            id=record_id,
            integration_type=integration_type,
            event_type=event_type.value,
            status=DeliveryStatus.FAILED,
            attempt=attempt - 1,
            max_attempts=_MAX_ATTEMPTS,
            error=last_error,
            timestamp=datetime.now(UTC).isoformat(),
        )

    def _build_body(
        self,
        integration_type: IntegrationType,
        event_type: WebhookEventType,
        payload: dict[str, Any],
    ) -> bytes:
        timestamp = datetime.now(UTC).isoformat()
        event_data = {
            "event": event_type.value,
            "timestamp": timestamp,
            "data": payload,
        }

        if integration_type == IntegrationType.SLACK:
            text = f"*{event_type.value}*\n{json.dumps(payload, indent=2)}"
            return json.dumps({"text": text}).encode()

        if integration_type == IntegrationType.MICROSOFT_TEAMS:
            return json.dumps({
                "@type": "MessageCard",
                "@context": "http://schema.org/extensions",
                "summary": event_type.value,
                "title": event_type.value,
                "text": json.dumps(payload, indent=2),
            }).encode()

        if integration_type == IntegrationType.DISCORD:
            content = f"**{event_type.value}**\n```json\n{json.dumps(payload, indent=2)}\n```"
            return json.dumps({"content": content}).encode()

        return json.dumps(event_data).encode()

    def _sign(self, body: bytes, secret: str) -> str:
        return hmac.new(secret.encode(), body, hashlib.sha256).hexdigest()

    def _audit_webhook(self, record: DeliveryRecord) -> None:
        action = AuditAction.NOTIFICATION_SENT if record.status == DeliveryStatus.DELIVERED else AuditAction.NOTIFICATION_FAILED
        self._audit.record(AuditEntry(
            action=action,
            resource_type="integration_webhook",
            success=record.status == DeliveryStatus.DELIVERED,
            reason=record.error or "",
            metadata={
                "integration_type": record.integration_type.value,
                "event_type": record.event_type,
                "attempt": record.attempt,
                "delivery_id": record.id,
            },
        ))

    def get_history(self, limit: int = 50) -> list[DeliveryRecord]:
        return sorted(self._history, key=lambda r: r.timestamp, reverse=True)[:limit]
