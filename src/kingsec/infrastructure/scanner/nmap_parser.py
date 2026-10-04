"""Parse Nmap XML output into domain ``Finding`` objects.

Pure and side-effect-free: given raw XML text from ``nmap -oX -``, produce
domain findings. Uses ``defusedxml.ElementTree`` at runtime for
protection against XML attacks (``xml.etree.ElementTree`` is imported only
under ``TYPE_CHECKING`` for static analysis). Malformed or incomplete data is
logged and skipped rather than failing the whole parse.

Severity mapping (conservative — Nmap itself doesn't rate vulns):
    Open port (no script)  → INFORMATIONAL
    Service with version   → LOW (configuration detail)
    Script vuln/exploit    → MEDIUM or HIGH (based on script id heuristics)
"""

from __future__ import annotations

import fnmatch
from datetime import UTC, datetime
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    # nosec B405 -- this import never executes at runtime (TYPE_CHECKING is
    # always False when Python actually runs this module); it exists only
    # so type checkers resolve ET.Element/ET.ParseError annotations below
    # against the stdlib's types, which defusedxml.ElementTree re-exports
    # but doesn't re-declare for static analysis. The real runtime parser
    # is defusedxml.ElementTree (the else branch), confirmed installed as
    # a declared dependency (pyproject.toml: defusedxml>=0.7.1,<1) and
    # confirmed importable. bandit's static pattern-match flags the mere
    # text of this import regardless of the TYPE_CHECKING guard - it is
    # not reachable code, so this is a false positive, not a real XXE
    # exposure. See Phase 12 report §5 for the full verdict.
    import xml.etree.ElementTree as ET  # nosec B405
else:
    import defusedxml.ElementTree as ET

from kingsec.domain import Evidence, Finding, Severity
from kingsec.infrastructure.logging import get_logger

_logger = get_logger("kingsec.infrastructure.scanner")

# Nmap script ids that signal elevated risk.
_HIGH_RISK_SCRIPTS = frozenset(
    {
        "ssl-poodle",
        "ssl-heartbleed",
        "ssl-dh-params",
        "ssl-cert-expired",
        "ssl-known-key",
    }
)
_MEDIUM_RISK_SCRIPTS = frozenset(
    {
        "ssl-enum-ciphers",
        "http-vuln-*",
        "smb-vuln-*",
    }
)


def _classify_script_severity(script_id: str) -> Severity:
    """Heuristic severity for Nmap script output using glob-style matching."""
    lower = script_id.lower()
    if any(fnmatch.fnmatch(lower, p.lower()) for p in _HIGH_RISK_SCRIPTS):
        return Severity.HIGH
    if any(fnmatch.fnmatch(lower, p.lower()) for p in _MEDIUM_RISK_SCRIPTS):
        return Severity.MEDIUM
    # Default: scripts that ran successfully but aren't known-vuln → LOW
    return Severity.LOW


# --- Open-port severity model -------------------------------------------------
# An open port is *exposure*, not a vulnerability - but not all exposure is
# equal. This model rates the service behind the port (by port number and/or
# nmap's detected service name) by how dangerous unauthenticated exposure of
# that service class has proven to be in practice:
#
# HIGH: remote-administration, file-sharing, and data-store protocols with a
#   documented history of wormable RCE or mass credential-theft / ransom
#   abuse when exposed (EternalBlue over SMB, BlueKeep over RDP, plaintext
#   Telnet/FTP credential capture, unauthenticated MongoDB/Redis/
#   Elasticsearch ransom attacks).
# MEDIUM: services where exposure is common and usually intentional, but
#   which are routinely brute-forced or abused for enumeration and
#   amplification (SSH, mail, DNS, SNMP, LDAP).
# LOW: an identified service with no such exposure history (HTTP/HTTPS and
#   anything else nmap could name) - still worth confirming as required
#   and patched, but not alarming on its own.
# INFORMATIONAL: nmap found an open port but could not identify the service -
#   there is nothing to rate beyond "something is listening".
#
# A port matches by number OR by detected service name, so (e.g.) RDP on a
# non-standard port is still rated High when nmap identifies the service,
# and port 3389 is still rated High when nmap cannot confirm the service.
_HIGH_RISK_PORTS: frozenset[int] = frozenset(
    {
        21,  # FTP - plaintext credentials
        23,  # Telnet - plaintext everything
        135,  # MS-RPC - DCOM/RPC remote-execution history
        137, 138, 139,  # NetBIOS - legacy enumeration and session abuse
        445,  # SMB - EternalBlue, ransomware lateral movement
        1433,  # MSSQL - database exposure, brute-force and data theft
        1521,  # Oracle DB - same class
        3306,  # MySQL - same class
        3389,  # RDP - BlueKeep, mass brute-forcing
        5432,  # PostgreSQL - same class as other databases
        *range(5900, 5910),  # VNC - weak/absent authentication history
        6379,  # Redis - unauthenticated ransom attacks
        9200,  # Elasticsearch - unauthenticated data exposure
        11211,  # memcached - unauthenticated, amplification abuse
        27017,  # MongoDB - unauthenticated ransom attacks
    }
)
_HIGH_RISK_SERVICES: frozenset[str] = frozenset(
    {
        "ftp",
        "telnet",
        "msrpc",
        "netbios-ns",
        "netbios-dgm",
        "netbios-ssn",
        "microsoft-ds",
        "smb",
        "ms-wbt-server",  # nmap's name for RDP
        "rdp",
        "vnc",
        "ms-sql-s",
        "mssql",
        "oracle",
        "tns",  # Oracle Transparent Network Substrate
        "mysql",
        "postgresql",
        "redis",
        "mongodb",
        "mongod",
        "elasticsearch",
        "memcached",
        "couchdb",
    }
)
_MEDIUM_RISK_PORTS: frozenset[int] = frozenset(
    {
        22,  # SSH - brute-forced constantly; verify hardening
        25,  # SMTP - spam relay / enumeration abuse
        53,  # DNS - amplification, zone-transfer recon
        110,  # POP3 - credential brute-forcing
        143,  # IMAP - same class
        161,  # SNMP - community-string enumeration
        389,  # LDAP - directory enumeration
        636,  # LDAPS - same class, encrypted but still recon
        993,  # IMAPS
        995,  # POP3S
    }
)
_MEDIUM_RISK_SERVICES: frozenset[str] = frozenset(
    {
        "ssh",
        "smtp",
        "domain",  # nmap's name for DNS
        "pop3",
        "imap",
        "snmp",
        "ldap",
    }
)

_SEVERITY_RATIONALE: dict[Severity, str] = {
    Severity.HIGH: (
        "Rated High: remote-administration, file-sharing, or data-store "
        "service with a documented history of remote exploitation or mass "
        "abuse when exposed without authentication."
    ),
    Severity.MEDIUM: (
        "Rated Medium: service routinely probed, brute-forced, or abused "
        "for enumeration when exposed; verify the exposure is intentional "
        "and the service is hardened."
    ),
    Severity.LOW: (
        "Rated Low: identified service with no such exposure history; "
        "confirm it is required, patched, and configured per vendor "
        "hardening guidance."
    ),
    Severity.INFORMATIONAL: (
        "Rated Informational: nmap could not identify the listening "
        "service, so exposure risk cannot be assessed from the port alone."
    ),
}


def _classify_port_severity(portid: str, service_name: str) -> tuple[Severity, str]:
    """Rate an open port by the risk class of the service behind it.

    Returns (severity, rationale). ``portid`` is nmap's raw string port
    number; a non-numeric value simply skips the port-number check rather
    than failing. ``service_name`` is nmap's detected service name (may be
    empty when unidentified).
    """
    try:
        port = int(portid)
    except (TypeError, ValueError):
        port = None
    service = service_name.strip().lower()
    if (port is not None and port in _HIGH_RISK_PORTS) or service in _HIGH_RISK_SERVICES:
        severity = Severity.HIGH
    elif (port is not None and port in _MEDIUM_RISK_PORTS) or service in _MEDIUM_RISK_SERVICES:
        severity = Severity.MEDIUM
    elif service:
        severity = Severity.LOW
    else:
        severity = Severity.INFORMATIONAL
    return severity, _SEVERITY_RATIONALE[severity]


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

        # Base finding: open port. Severity comes from the port-severity
        # model (risk class of the service behind the port), not from
        # whether nmap happened to fingerprint a product banner - and the
        # rationale is recorded in the description so the rating is
        # explainable on the report. affected_asset is the concrete host
        # nmap probed, not the assessment-level target the operator typed.
        title = f"Open port {portid}/{protocol}"
        severity, rationale = _classify_port_severity(portid, service_name)
        description = f"Port {portid}/{protocol} is open — {service_desc}. {rationale}"
        target_label = hostname or addr
        if hostname:
            target_label += f" ({addr})"

        finding = Finding.create(
            title=title, description=description, severity=severity, affected_asset=addr
        )
        finding.add_evidence(
            Evidence(
                summary=f"Port {portid}/{protocol} open on {target_label}",
                detail=(f"port: {portid}/{protocol} | state: open | service: {service_desc} | addr: {addr}"),
                collected_at=datetime.now(UTC),
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
                affected_asset=addr,
            )
            script_finding.add_evidence(
                Evidence(
                    summary=f"Script '{script_id}' on port {portid}/{protocol}",
                    detail=f"script-id: {script_id} | output: {script_output.strip()[:500]}",
                    collected_at=datetime.now(UTC),
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
        except Exception as exc:
            _logger.warning("skipping malformed host element", error=str(exc))

    return findings
