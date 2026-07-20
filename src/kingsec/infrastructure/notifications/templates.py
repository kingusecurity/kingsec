from __future__ import annotations

import re

from kingsec.application.ports.outbound import TemplateRendererPort
from kingsec.domain.notification import NotificationChannel, NotificationPriority, NotificationTemplate

_DEFAULT_TEMPLATES: dict[tuple[str, str], NotificationTemplate] = {
    ("scan_started", "email"): NotificationTemplate(
        event_type="scan_started",
        channel=NotificationChannel.EMAIL,
        subject_template="Scan Started: {{target}}",
        body_template="Scan started for {{target}} using {{scanner}}.",
    ),
    ("scan_completed", "email"): NotificationTemplate(
        event_type="scan_completed",
        channel=NotificationChannel.EMAIL,
        subject_template="Scan Completed: {{target}}",
        body_template="Scan completed for {{target}}.\nDuration: {{duration}}\nRisk: {{risk}}",
        priority=NotificationPriority.HIGH,
    ),
    ("scan_failed", "email"): NotificationTemplate(
        event_type="scan_failed",
        channel=NotificationChannel.EMAIL,
        subject_template="Scan Failed: {{target}}",
        body_template="Scan failed for {{target}}.\nError: {{error}}",
        priority=NotificationPriority.CRITICAL,
    ),
    ("job_completed", "email"): NotificationTemplate(
        event_type="job_completed",
        channel=NotificationChannel.EMAIL,
        subject_template="Job Completed: {{job_id}}",
        body_template="Scan job {{job_id}} completed successfully.",
    ),
    ("job_failed", "email"): NotificationTemplate(
        event_type="job_failed",
        channel=NotificationChannel.EMAIL,
        subject_template="Job Failed: {{job_id}}",
        body_template="Scan job {{job_id}} failed.\nError: {{error}}",
        priority=NotificationPriority.CRITICAL,
    ),
    ("password_changed", "email"): NotificationTemplate(
        event_type="password_changed",
        channel=NotificationChannel.EMAIL,
        subject_template="Password Changed",
        body_template="Your password was changed successfully.",
    ),
    ("login_failed", "email"): NotificationTemplate(
        event_type="login_failed",
        channel=NotificationChannel.EMAIL,
        subject_template="Failed Login Attempt",
        body_template="A failed login attempt was detected for your account.",
        priority=NotificationPriority.HIGH,
    ),
    ("api_key_created", "email"): NotificationTemplate(
        event_type="api_key_created",
        channel=NotificationChannel.EMAIL,
        subject_template="API Key Created",
        body_template="A new API key was created for your account.",
    ),
    ("api_key_revoked", "email"): NotificationTemplate(
        event_type="api_key_revoked",
        channel=NotificationChannel.EMAIL,
        subject_template="API Key Revoked",
        body_template="An API key was revoked for your account.",
    ),
    ("secret_rotated", "email"): NotificationTemplate(
        event_type="secret_rotated",
        channel=NotificationChannel.EMAIL,
        subject_template="Secret Rotated",
        body_template="A secret was rotated for your account.",
    ),
}


class JinjaTemplateRenderer(TemplateRendererPort):
    def __init__(self) -> None:
        self._templates = dict(_DEFAULT_TEMPLATES)

    def render(self, template: NotificationTemplate, variables: dict[str, str]) -> tuple[str, str]:
        subject = _render_string(template.subject_template, variables)
        body = _render_string(template.body_template, variables)
        return subject, body

    def get_template(self, event_type: str, channel: str) -> NotificationTemplate | None:
        return self._templates.get((event_type, channel))

    def register_template(self, template: NotificationTemplate) -> None:
        self._templates[(template.event_type, template.channel.value)] = template


def _render_string(template: str, variables: dict[str, str]) -> str:
    def _replace(match: re.Match[str]) -> str:
        key = match.group(1).strip()
        return variables.get(key, match.group(0))

    return re.sub(r"\{\{(\w+)\}\}", _replace, template)
