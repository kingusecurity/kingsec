from __future__ import annotations

import json
from typing import Any
from urllib.request import Request, urlopen

from kingsec.application.ports.outbound import AuditPublisher, TicketingPort
from kingsec.domain.audit import AuditAction, AuditEntry
from kingsec.domain.integration import IntegrationType, TicketReference
from kingsec.infrastructure.config.models import IntegrationSettings
from kingsec.infrastructure.logging import get_logger
from kingsec.infrastructure.notifications.url_validator import SSRFError, validate_url

logger = get_logger("kingsec.infrastructure.integrations.ticketing")


class TicketingService(TicketingPort):
    def __init__(self, settings: IntegrationSettings, audit: AuditPublisher) -> None:
        self._settings = settings
        self._audit = audit
        self._tickets: list[TicketReference] = []

    def create_ticket(
        self,
        system: IntegrationType,
        finding_id: str,
        title: str,
        description: str,
        severity: str,
        assessment_target: str,
    ) -> TicketReference | None:
        if self._is_duplicate(finding_id, system):
            logger.info("Duplicate ticket skipped for finding %s on %s", finding_id, system.value)
            return None

        adapter = self._get_adapter(system)
        if adapter is None:
            return None

        try:
            external_id, external_url = adapter(title, description, severity, assessment_target)
            ref = TicketReference(
                finding_id=finding_id,
                system=system,
                external_id=external_id,
                external_url=external_url,
            )
            self._tickets.append(ref)
            self._audit_ticket(system, ref, success=True)
            return ref
        except Exception as exc:
            logger.warning("Ticket creation failed for %s: %s", system.value, exc)
            self._audit_ticket(system, None, success=False, error=str(exc))
            return None

    def _is_duplicate(self, finding_id: str, system: IntegrationType) -> bool:
        return any(t.finding_id == finding_id and t.system == system for t in self._tickets)

    def _get_adapter(self, system: IntegrationType) -> Any | None:
        adapters = {
            IntegrationType.JIRA: self._jira_create,
            IntegrationType.GITHUB_ISSUES: self._github_create,
            IntegrationType.GITLAB_ISSUES: self._gitlab_create,
        }
        adapter = adapters.get(system)
        if adapter is None:
            logger.warning("No adapter for integration type: %s", system.value)
        return adapter

    def _jira_create(self, title: str, description: str, severity: str, target: str) -> tuple[str, str]:
        jira_token = self._settings.jira_api_token.get_secret_value()
        if not self._settings.jira_url or not self._settings.jira_email or not jira_token:
            raise RuntimeError("Jira not configured")
        url = f"{self._settings.jira_url.rstrip('/')}/rest/api/2/issue"
        try:
            validate_url(url)
        except SSRFError as exc:
            raise RuntimeError(f"Jira URL blocked by SSRF protection: {exc}") from exc
        auth = f"{self._settings.jira_email}:{jira_token}"
        import base64
        encoded = base64.b64encode(auth.encode()).decode()
        body = json.dumps({
            "fields": {
                "project": {"key": self._settings.jira_project_key},
                "summary": f"[KingSec] {title}",
                "description": f"*Severity:* {severity}\n*Target:* {target}\n\n{description}",
                "issuetype": {"name": "Bug"},
                "labels": ["security", "kingsec", severity.lower()],
            }
        }).encode()
        req = Request(url, data=body, method="POST")
        req.add_header("Authorization", f"Basic {encoded}")
        req.add_header("Content-Type", "application/json")
        with urlopen(req, timeout=15) as resp:
            data = json.loads(resp.read().decode())
        key = data.get("key", "?")
        browse_url = f"{self._settings.jira_url.rstrip('/')}/browse/{key}"
        return key, browse_url

    def _github_create(self, title: str, description: str, severity: str, target: str) -> tuple[str, str]:
        gh_token = self._settings.github_token.get_secret_value()
        if not gh_token or not self._settings.github_repo:
            raise RuntimeError("GitHub not configured")
        url = f"https://api.github.com/repos/{self._settings.github_repo}/issues"
        try:
            validate_url(url)
        except SSRFError as exc:
            raise RuntimeError(f"GitHub URL blocked by SSRF protection: {exc}") from exc
        body = json.dumps({
            "title": f"[KingSec] {title}",
            "body": f"**Severity:** {severity}\n**Target:** {target}\n\n{description}\n\n---\n*Created by KingSec*",
            "labels": ["security", severity.lower()],
        }).encode()
        req = Request(url, data=body, method="POST")
        req.add_header("Authorization", f"Bearer {gh_token}")
        req.add_header("Content-Type", "application/json")
        req.add_header("Accept", "application/vnd.github.v3+json")
        with urlopen(req, timeout=15) as resp:
            data = json.loads(resp.read().decode())
        return str(data.get("number", "")), data.get("html_url", "")

    def _gitlab_create(self, title: str, description: str, severity: str, target: str) -> tuple[str, str]:
        gl_token = self._settings.gitlab_token.get_secret_value()
        if not gl_token or not self._settings.gitlab_project_id:
            raise RuntimeError("GitLab not configured")
        base_url = self._settings.gitlab_url.rstrip("/") or "https://gitlab.com"
        url = f"{base_url}/api/v4/projects/{self._settings.gitlab_project_id}/issues"
        try:
            validate_url(url)
        except SSRFError as exc:
            raise RuntimeError(f"GitLab URL blocked by SSRF protection: {exc}") from exc
        body = json.dumps({
            "title": f"[KingSec] {title}",
            "description": f"**Severity:** {severity}\n**Target:** {target}\n\n{description}\n\n---\n*Created by KingSec*",
            "labels": "security," + severity.lower(),
        }).encode()
        req = Request(url, data=body, method="POST")
        req.add_header("PRIVATE-TOKEN", gl_token)
        req.add_header("Content-Type", "application/json")
        with urlopen(req, timeout=15) as resp:
            data = json.loads(resp.read().decode())
        return str(data.get("iid", "")), data.get("web_url", "")

    def get_tickets(self, finding_id: str | None = None) -> list[TicketReference]:
        if finding_id:
            return [t for t in self._tickets if t.finding_id == finding_id]
        return list(self._tickets)

    def _audit_ticket(self, system: IntegrationType, ref: TicketReference | None, success: bool, error: str = "") -> None:
        self._audit.record(AuditEntry(
            action=AuditAction.NOTIFICATION_SENT if success else AuditAction.NOTIFICATION_FAILED,
            resource_type="integration_ticket",
            success=success,
            reason=error,
            metadata={
                "system": system.value,
                "external_id": ref.external_id if ref else None,
                "external_url": ref.external_url if ref else None,
                "finding_id": ref.finding_id if ref else None,
            },
        ))
