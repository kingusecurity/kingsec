from __future__ import annotations

from typing import TYPE_CHECKING, Any

from fastapi import APIRouter, Depends, HTTPException, Request

from kingsec.application.ports.outbound import AuditPublisher
from kingsec.domain.audit import AuditAction, AuditEntry
from kingsec.domain.integration import IntegrationType, WebhookEventType
from kingsec.infrastructure.config.models import IntegrationSettings
from kingsec.infrastructure.integrations.email_service import EmailNotificationService
from kingsec.infrastructure.integrations.siem_service import SIEMExportService
from kingsec.infrastructure.integrations.ticketing_service import TicketingService
from kingsec.infrastructure.integrations.webhook_service import WebhookDeliveryService

from .auth import require_admin
from .dependencies import get_application

if TYPE_CHECKING:
    from kingsec.bootstrap.application import Application

router = APIRouter(prefix="/api/v1/integrations", tags=["integrations"], dependencies=[Depends(require_admin)])


def _settings(request: Request) -> IntegrationSettings:
    app: Application = get_application(request)
    return app.settings.integrations


def _resolve(request: Request, stype: type) -> Any:
    app: Application = get_application(request)
    svc = app.resolve(stype)
    if svc is None:
        raise HTTPException(status_code=500, detail=f"Service {stype.__name__} not available")
    return svc


@router.get("")
async def list_integrations(request: Request) -> dict[str, Any]:
    settings = _settings(request)
    return {
        "integrations": [
            {"type": "slack", "configured": bool(settings.slack_webhook_url), "label": "Slack"},
            {"type": "microsoft_teams", "configured": bool(settings.teams_webhook_url), "label": "Microsoft Teams"},
            {"type": "discord", "configured": bool(settings.discord_webhook_url), "label": "Discord"},
            {"type": "generic_webhook", "configured": bool(settings.generic_webhook_url), "label": "Generic Webhook"},
            {"type": "email", "configured": bool(settings.smtp_host), "label": "Email (SMTP)"},
            {"type": "jira", "configured": bool(settings.jira_url), "label": "Jira"},
            {"type": "github_issues", "configured": bool(settings.github_token), "label": "GitHub Issues"},
            {"type": "gitlab_issues", "configured": bool(settings.gitlab_token), "label": "GitLab Issues"},
            {"type": "splunk", "configured": bool(settings.splunk_hec_url), "label": "Splunk HEC"},
            {"type": "sentinel", "configured": bool(settings.sentinel_workspace_id), "label": "Microsoft Sentinel"},
            {"type": "elastic", "configured": bool(settings.elastic_api_key), "label": "Elastic"},
        ],
    }


@router.post("/test/{integration_type}")
async def test_integration(integration_type: str, request: Request) -> dict[str, Any]:
    settings = _settings(request)
    audit: AuditPublisher = _resolve(request, AuditPublisher)

    try:
        itype = IntegrationType(integration_type)
    except ValueError:
        raise HTTPException(status_code=400, detail=f"Unknown integration type: {integration_type}") from None

    config_map = {
        IntegrationType.SLACK: settings.slack_webhook_url,
        IntegrationType.MICROSOFT_TEAMS: settings.teams_webhook_url,
        IntegrationType.DISCORD: settings.discord_webhook_url,
        IntegrationType.WEBHOOK: settings.generic_webhook_url,
        IntegrationType.EMAIL: settings.smtp_host,
        IntegrationType.JIRA: settings.jira_url,
        IntegrationType.GITHUB_ISSUES: settings.github_token,
        IntegrationType.GITLAB_ISSUES: settings.gitlab_token,
        IntegrationType.SPLUNK: settings.splunk_hec_url,
        IntegrationType.SENTINEL: settings.sentinel_workspace_id,
        IntegrationType.ELASTIC: settings.elastic_api_key,
    }

    configured = bool(config_map.get(itype))
    if not configured:
        audit.record(AuditEntry(
            action=AuditAction.INTEGRATION_TEST_FAILED,
            resource_type="integration",
            success=False,
            reason="Integration not configured",
            metadata={"integration_type": itype.value},
        ))
        return {"status": "not_configured", "message": f"{itype.value} is not configured"}

    webhook_types = {IntegrationType.SLACK, IntegrationType.MICROSOFT_TEAMS, IntegrationType.DISCORD, IntegrationType.WEBHOOK}
    success = False

    if itype in webhook_types:
        svc: Any = _resolve(request, WebhookDeliveryService)
        test_payload = {"test": True, "message": "KingSec integration test"}
        records = svc.deliver(WebhookEventType.ASSESSMENT_STARTED, test_payload)
        success = any(r.status.value == "delivered" for r in records)
    elif itype == IntegrationType.EMAIL:
        svc = _resolve(request, EmailNotificationService)
        record = svc.send_raw(
            to_addresses=[settings.smtp_from_address] if settings.smtp_from_address else ["test@localhost"],
            subject="KingSec Integration Test",
            html_body="<h1>Test</h1><p>KingSec email integration test</p>",
        )
        success = record.status.value == "delivered"
    elif itype in {IntegrationType.JIRA, IntegrationType.GITHUB_ISSUES, IntegrationType.GITLAB_ISSUES}:
        svc = _resolve(request, TicketingService)
        ref = svc.create_ticket(itype, "test", "KingSec Integration Test", "Integration test", "info", "test-target")
        success = ref is not None
    elif itype in {IntegrationType.SPLUNK, IntegrationType.SENTINEL, IntegrationType.ELASTIC}:
        svc = _resolve(request, SIEMExportService)
        test_finding: list[dict[str, Any]] = [{"finding_id": "test", "title": "Test Finding", "severity": "informational"}]
        results = svc.export_findings(test_finding, [itype])
        success = any(r.success for r in results)

    status_text = "connected" if success else "failed"
    audit.record(AuditEntry(
        action=AuditAction.INTEGRATION_CONNECTED if success else AuditAction.INTEGRATION_DISCONNECTED,
        resource_type="integration",
        success=success,
        metadata={"integration_type": itype.value},
    ))

    return {"status": status_text, "integration_type": itype.value, "success": success}


@router.get("/webhook/history")
async def webhook_history(limit: int = 50, request: Request = None) -> dict[str, Any]:  # type: ignore[assignment]
    svc: Any = _resolve(request, WebhookDeliveryService)
    records = svc.get_history(limit=limit)
    return {
        "records": [
            {
                "id": r.id,
                "integration_type": r.integration_type.value,
                "event_type": r.event_type,
                "status": r.status.value,
                "attempt": r.attempt,
                "error": r.error,
                "timestamp": r.timestamp,
            }
            for r in records
        ],
        "total": len(records),
    }


@router.get("/email/history")
async def email_history(limit: int = 50, request: Request = None) -> dict[str, Any]:  # type: ignore[assignment]
    svc: Any = _resolve(request, EmailNotificationService)
    records = svc.get_history(limit=limit)
    return {
        "records": [
            {
                "id": r.id,
                "event_type": r.event_type,
                "status": r.status.value,
                "error": r.error,
                "timestamp": r.timestamp,
            }
            for r in records
        ],
        "total": len(records),
    }


@router.get("/tickets")
async def list_tickets(finding_id: str | None = None, request: Request = None) -> dict[str, Any]:  # type: ignore[assignment]
    svc: Any = _resolve(request, TicketingService)
    tickets = svc.get_tickets(finding_id=finding_id)
    return {
        "tickets": [
            {
                "finding_id": t.finding_id,
                "system": t.system.value,
                "external_id": t.external_id,
                "external_url": t.external_url,
                "created_at": t.created_at,
                "synced": t.synced,
            }
            for t in tickets
        ],
        "total": len(tickets),
    }
