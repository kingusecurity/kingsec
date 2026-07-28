from __future__ import annotations

from dataclasses import dataclass, field
from datetime import UTC, datetime
from enum import StrEnum


class IntegrationType(StrEnum):
    WEBHOOK = "webhook"
    SLACK = "slack"
    MICROSOFT_TEAMS = "microsoft_teams"
    DISCORD = "discord"
    EMAIL = "email"
    JIRA = "jira"
    GITHUB_ISSUES = "github_issues"
    GITLAB_ISSUES = "gitlab_issues"
    SPLUNK = "splunk"
    SENTINEL = "sentinel"
    ELASTIC = "elastic"


class IntegrationStatus(StrEnum):
    CONNECTED = "connected"
    DISCONNECTED = "disconnected"
    ERROR = "error"


class WebhookEventType(StrEnum):
    ASSESSMENT_STARTED = "assessment.started"
    ASSESSMENT_COMPLETED = "assessment.completed"
    ASSESSMENT_FAILED = "assessment.failed"
    CRITICAL_FINDING = "finding.critical"
    REPORT_GENERATED = "report.generated"


class DeliveryStatus(StrEnum):
    PENDING = "pending"
    DELIVERED = "delivered"
    FAILED = "failed"
    RETRYING = "retrying"


@dataclass(frozen=True)
class IntegrationConfig:
    integration_type: IntegrationType
    enabled: bool = False
    config: dict[str, object] = field(default_factory=dict)
    last_status: IntegrationStatus = IntegrationStatus.DISCONNECTED
    last_delivery: str | None = None
    last_error: str | None = None


@dataclass(frozen=True)
class DeliveryRecord:
    id: str
    integration_type: IntegrationType
    event_type: str
    status: DeliveryStatus
    attempt: int
    max_attempts: int
    response: str | None = None
    error: str | None = None
    timestamp: str = field(default_factory=lambda: datetime.now(UTC).isoformat())


@dataclass(frozen=True)
class TicketReference:
    finding_id: str
    system: IntegrationType
    external_id: str
    external_url: str
    created_at: str = field(default_factory=lambda: datetime.now(UTC).isoformat())
    synced: bool = True


@dataclass(frozen=True)
class SIEMBatchResult:
    integration_type: IntegrationType
    count: int
    success: bool
    error: str | None = None
    timestamp: str = field(default_factory=lambda: datetime.now(UTC).isoformat())
