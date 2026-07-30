from __future__ import annotations

import logging
from typing import Any

from kingsec.domain.playbook import (
    ActionExecutionLog,
    PlaybookAction,
    PlaybookActionType,
)

from .ports import (
    AiCopilotPort,
    AlertPort,
    AssessmentPort,
    AssetPort,
    ExternalTicketingPort,
    InvestigationNotePort,
    NotificationPort,
    ReportGeneratorPort,
    SiemPort,
)

logger = logging.getLogger(__name__)


class ActionExecutor:
    def __init__(
        self,
        notification: NotificationPort | None = None,
        ticketing: ExternalTicketingPort | None = None,
        assessment: AssessmentPort | None = None,
        ai_copilot: AiCopilotPort | None = None,
        siem: SiemPort | None = None,
        notes: InvestigationNotePort | None = None,
        asset: AssetPort | None = None,
        alert: AlertPort | None = None,
        report_generator: ReportGeneratorPort | None = None,
    ) -> None:
        self._notification = notification
        self._ticketing = ticketing
        self._assessment = assessment
        self._ai_copilot = ai_copilot
        self._siem = siem
        self._notes = notes
        self._asset = asset
        self._alert = alert
        self._report_generator = report_generator

    def execute(
        self,
        action: PlaybookAction,
        context: dict[str, Any],
    ) -> ActionExecutionLog:
        handler_map = {
            PlaybookActionType.GENERATE_REPORT: self._handle_generate_report,
            PlaybookActionType.NOTIFY_SLACK: self._handle_notify_slack,
            PlaybookActionType.NOTIFY_TEAMS: self._handle_notify_teams,
            PlaybookActionType.SEND_EMAIL: self._handle_send_email,
            PlaybookActionType.CREATE_JIRA_TICKET: self._handle_create_jira,
            PlaybookActionType.CREATE_GITHUB_ISSUE: self._handle_create_github,
            PlaybookActionType.RUN_ASSESSMENT: self._handle_run_assessment,
            PlaybookActionType.RUN_AI_COPILOT_SUMMARY: self._handle_ai_summary,
            PlaybookActionType.EXPORT_SIEM_EVENT: self._handle_export_siem,
            PlaybookActionType.CREATE_INVESTIGATION_NOTE: self._handle_create_note,
            PlaybookActionType.MARK_ASSET_CRITICAL: self._handle_mark_asset,
            PlaybookActionType.CHANGE_ALERT_STATUS: self._handle_change_alert,
            PlaybookActionType.CUSTOM_WEBHOOK: self._handle_webhook,
        }
        handler = handler_map.get(action.action_type)
        if not handler:
            return ActionExecutionLog(
                action_type=action.action_type.value,
                status="failed",
                error=f"No handler for {action.action_type}",
            )
        try:
            import time
            start = time.perf_counter()
            result = handler(action.config, context)
            elapsed_ms = int((time.perf_counter() - start) * 1000)
            return ActionExecutionLog(
                action_type=action.action_type.value,
                status="completed",
                output=str(result),
                duration_ms=elapsed_ms,
            )
        except Exception as exc:
            logger.exception("Action %s failed: %s", action.action_type, exc)
            return ActionExecutionLog(
                action_type=action.action_type.value,
                status="failed",
                error=str(exc),
            )

    def _handle_generate_report(self, config: dict[str, Any], ctx: dict[str, Any]) -> str:
        if not self._report_generator:
            return "Report generator not available"
        report_type = config.get("report_type", "executive")
        return self._report_generator.generate(report_type, ctx)

    def _handle_notify_slack(self, config: dict[str, Any], ctx: dict[str, Any]) -> str:
        if not self._notification:
            return "Notification service not available"
        message = config.get("message", "Playbook executed").format(**ctx)
        channel = config.get("channel", "")
        self._notification.send_slack(message, channel)
        return f"Slack notification sent to {channel or 'default'}"

    def _handle_notify_teams(self, config: dict[str, Any], ctx: dict[str, Any]) -> str:
        if not self._notification:
            return "Notification service not available"
        message = config.get("message", "Playbook executed").format(**ctx)
        webhook = config.get("webhook_url", "")
        self._notification.send_teams(message, webhook)
        return "Teams notification sent"

    def _handle_send_email(self, config: dict[str, Any], ctx: dict[str, Any]) -> str:
        if not self._notification:
            return "Notification service not available"
        to = config.get("to", [])
        subject = config.get("subject", "Playbook Notification").format(**ctx)
        body = config.get("body", "").format(**ctx)
        self._notification.send_email(to, subject, body)
        return f"Email sent to {to}"

    def _handle_create_jira(self, config: dict[str, Any], ctx: dict[str, Any]) -> str:
        if not self._ticketing:
            return "Ticketing service not available"
        summary = config.get("summary", "Playbook Issue").format(**ctx)
        description = config.get("description", "").format(**ctx)
        project = config.get("project", "")
        key = self._ticketing.create_jira_ticket(summary, description, project)
        return f"Jira ticket created: {key}"

    def _handle_create_github(self, config: dict[str, Any], ctx: dict[str, Any]) -> str:
        if not self._ticketing:
            return "Ticketing service not available"
        repo = config.get("repo", "")
        title = config.get("title", "Playbook Issue").format(**ctx)
        body = config.get("body", "").format(**ctx)
        url = self._ticketing.create_github_issue(repo, title, body)
        return f"GitHub issue created: {url}"

    def _handle_run_assessment(self, config: dict[str, Any], ctx: dict[str, Any]) -> str:
        if not self._assessment:
            return "Assessment service not available"
        asset_id = ctx.get("asset_id") or config.get("asset_id", "")
        assessment_id = self._assessment.run_assessment(asset_id)
        return f"Assessment started: {assessment_id}"

    def _handle_ai_summary(self, config: dict[str, Any], ctx: dict[str, Any]) -> str:
        if not self._ai_copilot:
            return "AI Copilot not available"
        summary = self._ai_copilot.generate_summary(config.get("context", ctx))
        return f"AI summary generated ({len(summary)} chars)"

    def _handle_export_siem(self, config: dict[str, Any], ctx: dict[str, Any]) -> str:
        if not self._siem:
            return "SIEM export not available"
        event = {**ctx, **config.get("event", {})}
        ref = self._siem.export_event(event)
        return f"SIEM event exported: {ref}"

    def _handle_create_note(self, config: dict[str, Any], ctx: dict[str, Any]) -> str:
        if not self._notes:
            return "Notes service not available"
        title = config.get("title", "Playbook Note").format(**ctx)
        content = config.get("content", "").format(**ctx)
        entity_type = config.get("entity_type", "playbook_execution")
        entity_id = ctx.get("execution_id", "")
        note_id = self._notes.create_note(title, content, entity_type, entity_id)
        return f"Note created: {note_id}"

    def _handle_mark_asset(self, config: dict[str, Any], ctx: dict[str, Any]) -> str:
        if not self._asset:
            return "Asset service not available"
        asset_id = ctx.get("asset_id") or config.get("asset_id", "")
        if not asset_id:
            return "No asset_id available"
        self._asset.mark_critical(asset_id)
        return f"Asset {asset_id} marked critical"

    def _handle_change_alert(self, config: dict[str, Any], ctx: dict[str, Any]) -> str:
        if not self._alert:
            return "Alert service not available"
        alert_id = ctx.get("alert_id") or config.get("alert_id", "")
        status = config.get("status", "acknowledged")
        if not alert_id:
            return "No alert_id available"
        self._alert.change_status(alert_id, status)
        return f"Alert {alert_id} status changed to {status}"

    def _handle_webhook(self, config: dict[str, Any], ctx: dict[str, Any]) -> str:
        import json
        import urllib.request
        url = config.get("url", "")
        if not url:
            return "No webhook URL configured"
        from kingsec.infrastructure.notifications.url_validator import SSRFError, validate_url

        try:
            validate_url(url)
        except SSRFError as exc:
            raise RuntimeError(f"Webhook URL blocked by SSRF protection: {exc}") from exc
        payload = config.get("payload", {}).copy()
        payload.update(ctx)
        data = json.dumps(payload).encode()
        req = urllib.request.Request(url, data=data, headers={"Content-Type": "application/json"})
        urllib.request.urlopen(req, timeout=30)
        return f"Webhook sent to {url}"
