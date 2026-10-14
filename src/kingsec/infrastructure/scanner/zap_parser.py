"""Parse OWASP ZAP JSON report output into domain ``Finding`` objects.

Pure and side-effect-free: given raw stdout JSON from ZAP, produce
domain findings. Uses only the standard library (``json``). Malformed or
incomplete records are logged and skipped rather than failing the whole parse.

ZAP JSON report format (the Traditional JSON report ZAP's ``-quickout``
writes - see https://www.zaproxy.org/docs/desktop/addons/report-generation/report-traditional-json/):
    Top-level dict with ``site`` array. Each site contains ``alerts`` array.
    Each alert contains: ``alert``, ``riskcode``, ``confidence``, ``desc``
    (HTML), ``solution``, ``reference``, and ``instances`` - an array of
    per-occurrence dicts with ``uri``, ``method``, ``param``, ``attack``
    and ``evidence``. There is NO top-level ``url``/``param``/``description``
    in the real format; those spellings are accepted as fallbacks for
    normalized fixtures.

Risk mapping:
    High (riskcode 3)       → HIGH
    Medium (riskcode 2)     → MEDIUM
    Low (riskcode 1)        → LOW
    Informational (riskcode 0) → INFORMATIONAL
"""

from __future__ import annotations

import json
import re
from datetime import UTC, datetime
from typing import Any

from kingsec.domain import Evidence, Finding, Recommendation, Severity
from kingsec.infrastructure.logging import get_logger

_logger = get_logger("kingsec.infrastructure.scanner")

_STRIP_TAGS_RE = re.compile(r"<[^>]+>")


def _strip_html(text: str) -> str:
    """Remove HTML tags for human-readable prose (ZAP's ``desc`` is HTML)."""
    return _STRIP_TAGS_RE.sub("", text or "").strip()


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


def _parse_alerts(alerts: list[dict[str, Any]], site_url: str) -> list[Finding]:
    """Parse the alerts array from a ZAP site."""
    findings: list[Finding] = []

    for alert in alerts:
        alert_name = alert.get("alert", "")
        risk = alert.get("riskcode", alert.get("risk", "0"))
        confidence = alert.get("confidence", "")
        # ZAP's real format names this field "desc" (HTML prose). The
        # "description" spelling is a fallback for normalized fixtures.
        # Reading only "description" silently dropped ZAP's description
        # for EVERY finding (proven live, 2026-10-14: all 13 ZAP findings
        # in a production report carried an empty description).
        description = alert.get("description") or alert.get("desc", "")
        solution = alert.get("solution", "")
        reference = alert.get("reference", "")
        # Per-occurrence detail lives under "instances" (uri/param/evidence);
        # the real format has no top-level "url"/"param". The first instance
        # carries the concrete location; the legacy top-level keys and the
        # site name remain as fallbacks.
        instances = alert.get("instances")
        first_instance = (
            instances[0] if isinstance(instances, list) and instances and isinstance(instances[0], dict) else {}
        )
        instance_count = len(instances) if isinstance(instances, list) else 0
        url = first_instance.get("uri") or alert.get("url") or site_url
        param = first_instance.get("param") or alert.get("param", "")
        instance_evidence = first_instance.get("evidence", "")

        severity = _map_risk(risk)

        title = f"{alert_name} — {url}"
        desc_parts = [f"alert: {alert_name}", f"risk: {risk}", f"url: {url}"]
        if param:
            desc_parts.append(f"param: {param}")
        if confidence:
            desc_parts.append(f"confidence: {confidence}")
        description_text = " | ".join(desc_parts)
        plain_description = _strip_html(str(description))
        if plain_description:
            # The scanner's own prose leads; the machine-readable meta line
            # follows so nothing the old shape carried is lost.
            description_text = f"{plain_description} | {description_text}"

        finding = Finding.create(
            title=title,
            description=description_text,
            severity=severity,
        )

        evidence_detail = (
            f"alert: {alert_name} | risk: {risk} | confidence: {confidence} | "
            f"url: {url} | param: {param} | description: {description[:200]} | "
            f"solution: {solution[:200]}"
        )
        if instance_evidence:
            evidence_detail += f" | evidence: {instance_evidence[:500]}"
        if instance_count > 1:
            evidence_detail += f" | instances: {instance_count}"
        if reference:
            evidence_detail += f" | reference: {reference[:500]}"

        finding.add_evidence(
            Evidence(
                summary=f"ZAP: {alert_name}",
                detail=evidence_detail,
                collected_at=datetime.now(UTC),
            )
        )

        # Solution → Recommendation
        if solution:
            finding.add_recommendation(
                Recommendation(
                    title="Remediation",
                    description=str(solution),
                    priority=severity,
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

        site_url = str(site.get("@name", site.get("host", "")) or "")
        alerts = site.get("alerts", [])
        if isinstance(alerts, list) and alerts:
            findings.extend(_parse_alerts(alerts, site_url))

    return findings
