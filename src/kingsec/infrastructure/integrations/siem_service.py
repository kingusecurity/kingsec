from __future__ import annotations

import hashlib
import hmac
import json
from base64 import b64encode
from datetime import UTC, datetime
from typing import Any
from urllib.request import Request, urlopen

from kingsec.application.errors import LicenseRequiredError
from kingsec.application.ports.outbound import AuditPublisher, SIEMExportPort
from kingsec.application.services.licensing import LicenseGate
from kingsec.domain.audit import AuditAction, AuditEntry
from kingsec.domain.integration import IntegrationType, SIEMBatchResult
from kingsec.infrastructure.config.models import IntegrationSettings
from kingsec.infrastructure.logging import get_logger
from kingsec.infrastructure.notifications.url_validator import SSRFError, validate_url

logger = get_logger("kingsec.infrastructure.integrations.siem")


class SIEMExportService(SIEMExportPort):
    def __init__(
        self,
        settings: IntegrationSettings,
        audit: AuditPublisher,
        license_gate: LicenseGate | None = None,
    ) -> None:
        self._settings = settings
        self._audit = audit
        self._license_gate = license_gate

    def export_findings(
        self,
        findings: list[dict[str, Any]],
        target_systems: list[IntegrationType] | None = None,
    ) -> list[SIEMBatchResult]:
        if self._license_gate is not None and not self._license_gate.can_use_integrations():
            raise LicenseRequiredError("Integrations", self._license_gate.current_edition().value)

        results: list[SIEMBatchResult] = []
        systems = target_systems or [
            IntegrationType.SPLUNK,
            IntegrationType.SENTINEL,
            IntegrationType.ELASTIC,
        ]

        for system in systems:
            result = self._export_to(system, findings)
            results.append(result)
            self._audit_siem(result)
        return results

    def _export_to(self, system: IntegrationType, findings: list[dict[str, Any]]) -> SIEMBatchResult:
        adapter = {
            IntegrationType.SPLUNK: self._splunk_send,
            IntegrationType.SENTINEL: self._sentinel_send,
            IntegrationType.ELASTIC: self._elastic_send,
        }.get(system)

        if adapter is None:
            return SIEMBatchResult(integration_type=system, count=0, success=False, error="No adapter")

        try:
            count = adapter(findings)
            return SIEMBatchResult(integration_type=system, count=count, success=True)
        except Exception as exc:
            logger.warning("SIEM export to %s failed: %s", system.value, exc)
            return SIEMBatchResult(integration_type=system, count=0, success=False, error=str(exc))

    def _build_events(self, findings: list[dict[str, Any]]) -> list[dict[str, Any]]:
        return [
            {
                "finding_id": f.get("finding_id", ""),
                "title": f.get("title", ""),
                "description": f.get("description", ""),
                "severity": f.get("severity", "informational"),
                "status": f.get("status", "open"),
                "assessment_id": f.get("assessment_id", ""),
                "target": f.get("target", ""),
                "discovered_at": f.get("discovered_at", ""),
                "source": "KingSec",
                "event_type": "finding",
                "timestamp": datetime.now(UTC).isoformat(),
            }
            for f in findings
        ]

    def _splunk_send(self, findings: list[dict[str, Any]]) -> int:
        url = self._settings.splunk_hec_url
        token = self._settings.splunk_hec_token.get_secret_value()
        if not url or not token:
            raise RuntimeError("Splunk HEC not configured")

        try:
            validate_url(url)
        except SSRFError as exc:
            raise RuntimeError(f"Splunk HEC URL blocked by SSRF protection: {exc}") from exc

        events = self._build_events(findings)
        payload = json.dumps({"event": events}).encode()
        req = Request(url, data=payload, method="POST")
        req.add_header("Authorization", f"Splunk {token}")
        req.add_header("Content-Type", "application/json")
        with urlopen(req, timeout=15):
            pass
        return len(findings)

    def _sentinel_send(self, findings: list[dict[str, Any]]) -> int:
        workspace_id = self._settings.sentinel_workspace_id
        shared_key = self._settings.sentinel_shared_key.get_secret_value()
        if not workspace_id or not shared_key:
            raise RuntimeError("Microsoft Sentinel not configured")

        events = self._build_events(findings)
        body = json.dumps(events).encode()
        rfc1123 = datetime.now(UTC).strftime("%a, %d %b %Y %H:%M:%S GMT")
        content_length = str(len(body))
        string_to_hash = f"POST\n{content_length}\napplication/json\nx-ms-date:{rfc1123}\n/api/logs"
        signed = hmac.new(b64encode(shared_key.encode()), string_to_hash.encode(), hashlib.sha256).digest()
        signature = b64encode(signed).decode()

        url = self._settings.sentinel_dce_url or f"https://{workspace_id}.ods.opinsights.azure.com"
        url = f"{url.rstrip('/')}/api/logs?api-version=2016-04-01"

        try:
            validate_url(url)
        except SSRFError as exc:
            raise RuntimeError(f"Sentinel URL blocked by SSRF protection: {exc}") from exc

        req = Request(url, data=body, method="POST")
        req.add_header("Content-Type", "application/json")
        req.add_header("Log-Type", "KingSec_Findings")
        req.add_header("x-ms-date", rfc1123)
        req.add_header("Authorization", f"SharedKey {workspace_id}:{signature}")
        with urlopen(req, timeout=15):
            pass
        return len(findings)

    def _elastic_send(self, findings: list[dict[str, Any]]) -> int:
        api_key = self._settings.elastic_api_key.get_secret_value()
        cloud_id = self._settings.elastic_cloud_id
        url = self._settings.elastic_url
        if not api_key or not (cloud_id or url):
            raise RuntimeError("Elastic not configured")

        endpoint = url or f"https://{cloud_id}.elastic.cloud"
        bulk_url = f"{endpoint.rstrip('/')}/_bulk"

        try:
            validate_url(bulk_url)
        except SSRFError as exc:
            raise RuntimeError(f"Elastic URL blocked by SSRF protection: {exc}") from exc

        lines: list[str] = []
        for f in findings:
            action = json.dumps({"index": {"_index": "kingsec-findings"}})
            doc = self._build_events([f])[0]
            lines.append(action)
            lines.append(json.dumps(doc))
        lines.append("")
        payload = "\n".join(lines).encode()

        req = Request(bulk_url, data=payload, method="POST")
        req.add_header("Authorization", f"ApiKey {api_key}")
        req.add_header("Content-Type", "application/x-ndjson")
        with urlopen(req, timeout=15):
            pass
        return len(findings)

    def _audit_siem(self, result: SIEMBatchResult) -> None:
        self._audit.record(AuditEntry(
            action=AuditAction.NOTIFICATION_SENT if result.success else AuditAction.NOTIFICATION_FAILED,
            resource_type="integration_siem",
            success=result.success,
            reason=result.error or "",
            metadata={
                "integration_type": result.integration_type.value,
                "count": result.count,
            },
        ))
