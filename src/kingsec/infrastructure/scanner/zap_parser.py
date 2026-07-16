"""Parse OWASP ZAP JSON report output into domain ``Finding`` objects.

Pure and side-effect-free: given raw stdout JSON from ZAP, produce
domain findings. Uses only the standard library (``json``). Malformed or
incomplete records are logged and skipped rather than failing the whole parse.

ZAP JSON report format:
    Top-level dict with ``site`` array. Each site contains ``alerts`` array.
    Each alert contains: ``alert``, ``riskcode``, ``confidence``,
    ``description``, ``solution``, ``reference``, ``url``, ``param``.

Risk mapping:
    High (riskcode 3)       → HIGH
    Medium (riskcode 2)     → MEDIUM
    Low (riskcode 1)        → LOW
    Informational (riskcode 0) → INFORMATIONAL
"""

from __future__ import annotations

import json
from datetime import datetime, timezone

from kingsec.domain import Evidence, Finding, Severity
from kingsec.infrastructure.logging import get_logger

_logger = get_logger("kingsec.infrastructure.scanner")

_RISK_MAP = {
    "3": Severity.HIGH,
    "High": Severity.HIGH,
    "2": Severity.MEDIUM,
    "Medium": Severity.MEDIUM,
    "1": Severity.LOW,
    "Low": Severity.LOW,
    "0": Severity.INFORMATIONAL,
    "Informational": Severity.INFORMATIONAL,
    "Information": Severity.INFORMATIONAL,
}


def _map_risk(risk: str | int) -> Severity:
    """Map ZAP risk code/string to domain Severity."""
    return _RISK_MAP.get(str(risk), Severity.INFORMATIONAL)


def _parse_alerts(alerts: list[dict], site_url: str) -> list[Finding]:
    """Parse the alerts array from a ZAP site."""
    findings: list[Finding] = []

    for alert in alerts:
        alert_name = alert.get("alert", "")
        risk = alert.get("riskcode", alert.get("risk", "0"))
        confidence = alert.get("confidence", "")
        description = alert.get("description", "")
        solution = alert.get("solution", "")
        reference = alert.get("reference", "")
        url = alert.get("url", site_url)
        param = alert.get("param", "")

        severity = _map_risk(risk)

        title = f"{alert_name} — {url}"
        desc_parts = [f"alert: {alert_name}", f"risk: {risk}", f"url: {url}"]
        if param:
            desc_parts.append(f"param: {param}")
        if confidence:
            desc_parts.append(f"confidence: {confidence}")
        description_text = " | ".join(desc_parts)

        finding = Finding.create(
            title=title,
            description=description_text,
            severity=severity,
        )
        finding.add_evidence(
            Evidence(
                summary=f"ZAP: {alert_name}",
                detail=(
                    f"alert: {alert_name} | risk: {risk} | confidence: {confidence} | "
                    f"url: {url} | param: {param} | description: {description[:200]} | "
                    f"solution: {solution[:200]} | reference: {reference[:200]}"
                ),
                collected_at=datetime.now(timezone.utc),
            )
        )
        findings.append(finding)

    return findings


def parse_zap_json(output: str) -> list[Finding]:
    """Parse ZAP stdout JSON into domain findings.

    Args:
        output: The raw stdout JSON captured from a ZAP scan.

    Returns:
        The findings parsed from the output (empty if there were none).
    """
    try:
        data = json.loads(output)
    except (json.JSONDecodeError, ValueError):
        _logger.debug("failed to parse zap JSON output")
        return []

    if not isinstance(data, dict):
        return []

    sites = data.get("site", [])
    if not isinstance(sites, list):
        return []

    findings: list[Finding] = []

    for site in sites:
        if not isinstance(site, dict):
            continue

        site_url = site.get("@name", site.get("host", ""))
        alerts = site.get("alerts", [])
        if isinstance(alerts, list) and alerts:
            findings.extend(_parse_alerts(alerts, site_url))

    return findings
