"""The 4 integration services implement their application-layer ports.

Scoped to this: integration_routes.py previously resolved these services by
their concrete infrastructure class (an import-linter violation for an
adapter reaching across to a sibling infrastructure module). It now resolves
by port instead, so these classes must satisfy the port contract.
"""

from __future__ import annotations

from kingsec.application.ports.outbound import (
    AuditPublisher,
    EmailNotificationPort,
    SIEMExportPort,
    TicketingPort,
    WebhookDeliveryPort,
)
from kingsec.domain.audit import AuditEntry
from kingsec.domain.integration import IntegrationType
from kingsec.infrastructure.config.models import IntegrationSettings
from kingsec.infrastructure.integrations.email_service import EmailNotificationService
from kingsec.infrastructure.integrations.siem_service import SIEMExportService
from kingsec.infrastructure.integrations.ticketing_service import TicketingService
from kingsec.infrastructure.integrations.webhook_service import WebhookDeliveryService


class _NullAuditPublisher(AuditPublisher):
    def record(self, entry: AuditEntry) -> None:
        pass


def _settings() -> IntegrationSettings:
    return IntegrationSettings()


class TestIntegrationServicesSatisfyPorts:
    def test_webhook_delivery_service_is_a_port(self) -> None:
        svc = WebhookDeliveryService(_settings(), _NullAuditPublisher())
        assert isinstance(svc, WebhookDeliveryPort)

    def test_email_notification_service_is_a_port(self) -> None:
        svc = EmailNotificationService(_settings(), _NullAuditPublisher())
        assert isinstance(svc, EmailNotificationPort)

    def test_ticketing_service_is_a_port(self) -> None:
        svc = TicketingService(_settings(), _NullAuditPublisher())
        assert isinstance(svc, TicketingPort)

    def test_siem_export_service_is_a_port(self) -> None:
        svc = SIEMExportService(_settings(), _NullAuditPublisher())
        assert isinstance(svc, SIEMExportPort)


class TestTicketingPortBehaviorUnchanged:
    def test_create_and_list_tickets_through_the_port_type(self) -> None:
        svc: TicketingPort = TicketingService(_settings(), _NullAuditPublisher())
        # No adapter is configured for jira in these settings, so creation is skipped
        # (returns None) rather than raising - the same behavior as before the port existed.
        ref = svc.create_ticket(IntegrationType.JIRA, "f1", "title", "desc", "high", "target")
        assert ref is None
        assert svc.get_tickets() == []
