from __future__ import annotations

import smtplib
import uuid
from datetime import UTC, datetime
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
from typing import Any

from kingsec.application.errors import LicenseRequiredError
from kingsec.application.ports.outbound import AuditPublisher, EmailNotificationPort
from kingsec.application.services.licensing import LicenseGate
from kingsec.domain.audit import AuditAction, AuditEntry
from kingsec.domain.integration import DeliveryRecord, DeliveryStatus, IntegrationType
from kingsec.infrastructure.config.models import IntegrationSettings
from kingsec.infrastructure.logging import get_logger

logger = get_logger("kingsec.infrastructure.integrations.email")

HTML_TEMPLATES: dict[str, tuple[str, str]] = {
    "assessment_complete": (
        "Assessment Complete: {target}",
        """<h2>Assessment Complete</h2>
<p>The assessment for <strong>{target}</strong> has completed.</p>
<table>
<tr><td>Status</td><td>{status}</td></tr>
<tr><td>Findings</td><td>{finding_count}</td></tr>
<tr><td>Highest Severity</td><td>{highest_severity}</td></tr>
</table>
<p><a href="{report_url}">View Report</a></p>""",
    ),
    "critical_findings": (
        "Critical Findings: {count} on {target}",
        """<h2>Critical Findings Detected</h2>
<p>{count} critical finding(s) were detected on <strong>{target}</strong>.</p>
<ul>{findings_list}</ul>
<p><a href="{findings_url}">View Findings</a></p>""",
    ),
    "weekly_summary": (
        "KingSec Weekly Summary - {date_range}",
        """<h2>Weekly Summary</h2>
<table>
<tr><td>Assessments Run</td><td>{assessments_run}</td></tr>
<tr><td>Total Findings</td><td>{total_findings}</td></tr>
<tr><td>Critical</td><td>{critical_count}</td></tr>
<tr><td>High</td><td>{high_count}</td></tr>
<tr><td>New Tickets</td><td>{tickets_created}</td></tr>
</table>
<p><a href="{dashboard_url}">View Dashboard</a></p>""",
    ),
    "report_ready": (
        "Report Ready: {target}",
        """<h2>Report Generated</h2>
<p>The report for <strong>{target}</strong> is ready for download.</p>
<table>
<tr><td>Verdict</td><td>{verdict}</td></tr>
<tr><td>Score</td><td>{score}</td></tr>
</table>
<p><a href="{report_url}">Download Report</a></p>""",
    ),
}

PLAIN_TEMPLATES: dict[str, str] = {
    "assessment_complete": "Assessment Complete: {target}\nStatus: {status}\nFindings: {finding_count}\nHighest Severity: {highest_severity}\nReport: {report_url}",
    "critical_findings": "Critical Findings: {count} on {target}\n{findings_list}\nView: {findings_url}",
    "weekly_summary": "Weekly Summary\nAssessments: {assessments_run}\nFindings: {total_findings}\nCritical: {critical_count}\nHigh: {high_count}\nDashboard: {dashboard_url}",
    "report_ready": "Report Ready: {target}\nVerdict: {verdict}\nScore: {score}\nDownload: {report_url}",
}


class EmailNotificationService(EmailNotificationPort):
    def __init__(
        self,
        settings: IntegrationSettings,
        audit: AuditPublisher,
        license_gate: LicenseGate | None = None,
    ) -> None:
        self._settings = settings
        self._audit = audit
        self._license_gate = license_gate
        self._history: list[DeliveryRecord] = []

    def _require_license(self) -> None:
        if self._license_gate is not None and not self._license_gate.can_use_integrations():
            raise LicenseRequiredError("Integrations", self._license_gate.current_edition().value)

    def send_template(
        self,
        template_name: str,
        to_addresses: list[str],
        variables: dict[str, Any],
    ) -> DeliveryRecord:
        self._require_license()
        record_id = str(uuid.uuid4())

        if not self._settings.smtp_host:
            return self._fail(record_id, "SMTP not configured")

        if template_name not in HTML_TEMPLATES:
            return self._fail(record_id, f"Unknown template: {template_name}")

        subject_tmpl, html_tmpl = HTML_TEMPLATES[template_name]
        plain_tmpl = PLAIN_TEMPLATES.get(template_name, "")

        subject = subject_tmpl.format(**variables)
        html_body = html_tmpl.format(**variables)
        plain_body = plain_tmpl.format(**variables) if plain_tmpl else ""

        return self._send(record_id, to_addresses, subject, html_body, plain_body, template_name)

    def send_raw(
        self,
        to_addresses: list[str],
        subject: str,
        html_body: str,
        plain_body: str | None = None,
    ) -> DeliveryRecord:
        self._require_license()
        record_id = str(uuid.uuid4())

        if not self._settings.smtp_host:
            return self._fail(record_id, "SMTP not configured")

        return self._send(record_id, to_addresses, subject, html_body, plain_body or "", "raw")

    def _send(
        self,
        record_id: str,
        to_addresses: list[str],
        subject: str,
        html_body: str,
        plain_body: str,
        template_name: str,
    ) -> DeliveryRecord:
        msg = MIMEMultipart("alternative")
        msg["Subject"] = subject
        msg["From"] = self._settings.smtp_from_address
        msg["To"] = ", ".join(to_addresses)

        if plain_body:
            msg.attach(MIMEText(plain_body, "plain"))
        msg.attach(MIMEText(html_body, "html"))

        try:
            with smtplib.SMTP(self._settings.smtp_host, self._settings.smtp_port, timeout=15) as server:
                if self._settings.smtp_use_tls:
                    server.starttls()
                if self._settings.smtp_username:
                    server.login(self._settings.smtp_username, self._settings.smtp_password.get_secret_value())
                server.sendmail(self._settings.smtp_from_address, to_addresses, msg.as_string())

            record = DeliveryRecord(
                id=record_id,
                integration_type=IntegrationType.EMAIL,
                event_type=template_name,
                status=DeliveryStatus.DELIVERED,
                attempt=1,
                max_attempts=3,
                timestamp=datetime.now(UTC).isoformat(),
            )
            logger.info("Email delivered: %s -> %s", subject, to_addresses)
        except Exception as exc:
            logger.warning("Email delivery failed: %s", exc)
            record = DeliveryRecord(
                id=record_id,
                integration_type=IntegrationType.EMAIL,
                event_type=template_name,
                status=DeliveryStatus.FAILED,
                attempt=1,
                max_attempts=3,
                error=str(exc),
                timestamp=datetime.now(UTC).isoformat(),
            )

        self._history.append(record)
        self._audit_email(record, to_addresses)
        return record

    def _fail(self, record_id: str, reason: str) -> DeliveryRecord:
        record = DeliveryRecord(
            id=record_id,
            integration_type=IntegrationType.EMAIL,
            event_type="error",
            status=DeliveryStatus.FAILED,
            attempt=1,
            max_attempts=3,
            error=reason,
            timestamp=datetime.now(UTC).isoformat(),
        )
        self._history.append(record)
        self._audit_email(record, [])
        return record

    def _audit_email(self, record: DeliveryRecord, to: list[str]) -> None:
        action = AuditAction.NOTIFICATION_SENT if record.status == DeliveryStatus.DELIVERED else AuditAction.NOTIFICATION_FAILED
        self._audit.record(AuditEntry(
            action=action,
            resource_type="integration_email",
            success=record.status == DeliveryStatus.DELIVERED,
            reason=record.error or "",
            metadata={
                "to": to,
                "template": record.event_type,
                "delivery_id": record.id,
            },
        ))

    def get_history(self, limit: int = 50) -> list[DeliveryRecord]:
        return sorted(self._history, key=lambda r: r.timestamp, reverse=True)[:limit]
