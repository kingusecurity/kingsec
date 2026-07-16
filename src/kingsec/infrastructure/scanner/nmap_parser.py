"""Parse Nmap XML output into domain ``Finding`` objects.

Pure and side-effect-free: given raw XML text from ``nmap -oX -``, produce
domain findings. Uses only the standard library (``xml.etree.ElementTree``).
Malformed or incomplete data is logged and skipped rather than failing the
whole parse.

Severity mapping (conservative — Nmap itself doesn't rate vulns):
    Open port (no script)  → INFORMATIONAL
    Service with version   → LOW (configuration detail)
    Script vuln/exploit    → MEDIUM or HIGH (based on script id heuristics)
"""

from __future__ import annotations

import xml.etree.ElementTree as ET
from datetime import datetime, timezone

from kingsec.domain import Evidence, Finding, Severity
from kingsec.infrastructure.logging import get_logger

_logger = get_logger("kingsec.infrastructure.scanner")

# Nmap script ids that signal elevated risk.
_HIGH_RISK_SCRIPTS = frozenset({
    "ssl-poodle", "ssl-heartbleed", "ssl-dh-params",
    "ssl-cert-expired", "ssl-known-key",
})
_MEDIUM_RISK_SCRIPTS = frozenset({
    "ssl-enum-ciphers", "http-vuln-*", "smb-vuln-*",
})


def _classify_script_severity(script_id: str) -> Severity:
    """Heuristic severity for Nmap script output."""
    lower = script_id.lower()
    if any(lower.startswith(p.replace("*", "")) for p in _HIGH_RISK_SCRIPTS):
        return Severity.HIGH
    if any(lower.startswith(p.replace("*", "")) for p in _MEDIUM_RISK_SCRIPTS):
        return Severity.MEDIUM
    # Default: scripts that ran successfully but aren't known-vuln → LOW
    return Severity.LOW


def _parse_host(host_el: ET.Element) -> list[Finding]:
    """Parse a single <host> element into findings."""
    findings: list[Finding] = []

    # Host address
    addr_el = host_el.find("address")
    addr = addr_el.get("addr", "unknown") if addr_el is not None else "unknown"

    # Hostname (if any)
    hostname_el = host_el.find(".//hostname")
    hostname = hostname_el.get("name", "") if hostname_el is not None else ""

    # Host status
    status_el = host_el.find("status")
    host_state = status_el.get("state", "unknown") if status_el is not None else "unknown"
    if host_state != "up":
        return findings

    # Ports
    ports_el = host_el.find("ports")
    if ports_el is None:
        return findings

    for port_el in ports_el.findall("port"):
        portid = port_el.get("portid", "?")
        protocol = port_el.get("protocol", "tcp")

        state_el = port_el.find("state")
        port_state = state_el.get("state", "unknown") if state_el is not None else "unknown"
        if port_state != "open":
            continue

        # Service info
        service_el = port_el.find("service")
        service_name = service_el.get("name", "") if service_el is not None else ""
        product = service_el.get("product", "") if service_el is not None else ""
        version = service_el.get("version", "") if service_el is not None else ""

        # Build service description
        svc_parts = [service_name] if service_name else []
        if product:
            svc_parts.append(product)
        if version:
            svc_parts.append(version)
        service_desc = " ".join(svc_parts) or "unknown service"

        # Base finding: open port
        title = f"Open port {portid}/{protocol}"
        description = f"Port {portid}/{protocol} is open — {service_desc}"
        target_label = hostname or addr
        if hostname:
            target_label += f" ({addr})"

        severity = Severity.INFORMATIONAL
        if product or version:
            severity = Severity.LOW

        finding = Finding.create(title=title, description=description, severity=severity)
        finding.add_evidence(
            Evidence(
                summary=f"Port {portid}/{protocol} open on {target_label}",
                detail=(
                    f"port: {portid}/{protocol} | state: open | "
                    f"service: {service_desc} | addr: {addr}"
                ),
                collected_at=datetime.now(timezone.utc),
            )
        )
        findings.append(finding)

        # Script output
        for script_el in port_el.findall("script"):
            script_id = script_el.get("id", "unknown")
            script_output = script_el.get("output", "")
            if not script_output:
                continue

            sev = _classify_script_severity(script_id)
            script_finding = Finding.create(
                title=f"Nmap script: {script_id}",
                description=script_output.strip(),
                severity=sev,
            )
            script_finding.add_evidence(
                Evidence(
                    summary=f"Script '{script_id}' on port {portid}/{protocol}",
                    detail=f"script-id: {script_id} | output: {script_output.strip()[:500]}",
                    collected_at=datetime.now(timezone.utc),
                )
            )
            findings.append(script_finding)

    return findings


def parse_nmap_xml(output: str) -> list[Finding]:
    """Parse Nmap XML stdout into domain findings.

    Args:
        output: The raw XML captured from ``nmap -oX -``.

    Returns:
        The findings parsed from the output (empty if there were none).
    """
    findings: list[Finding] = []

    stripped = output.strip()
    if not stripped:
        return findings

    try:
        root = ET.fromstring(stripped)
    except ET.ParseError as exc:
        _logger.warning("failed to parse nmap XML output", error=str(exc))
        return findings

    for host_el in root.findall(".//host"):
        try:
            findings.extend(_parse_host(host_el))
        except Exception as exc:  # noqa: BLE001
            _logger.warning("skipping malformed host element", error=str(exc))

    return findings
