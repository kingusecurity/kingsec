"""Parse OWASP Amass JSON output into domain ``Finding`` objects.

Pure and side-effect-free: given raw stdout text from Amass, produce
domain findings. Uses only the standard library (``json``). Malformed or
incomplete lines are logged and skipped rather than failing the whole parse.

Amass JSON output format (``amass enum -json -``):
    Each line is a separate JSON object representing a discovered asset.
    Keys: ``name``, ``domain``, ``addresses``, ``sources``, ``tag``.

Severity mapping (conservative):
    Public subdomain discovery          → INFORMATIONAL
    Cloud / infrastructure names        → LOW
    Sensitive / administrative names    → MEDIUM
"""

from __future__ import annotations

import json
from datetime import UTC, datetime

from kingsec.domain import Evidence, Finding, Severity
from kingsec.infrastructure.logging import get_logger

_logger = get_logger("kingsec.infrastructure.scanner")

# Cloud / infrastructure hostnames → LOW
_LOW_NAMES = frozenset(
    {
        "admin",
        "vpn",
        "dev",
        "stage",
        "staging",
        "internal",
        "api",
        "mail",
        "git",
        "jenkins",
        "kibana",
        "grafana",
        "cloud",
        "aws",
        "azure",
        "gcp",
        "cdn",
        "static",
        "ci",
        "cd",
        "gitlab",
        "bitbucket",
        "prometheus",
        "monitor",
        "metrics",
        "k8s",
        "kubernetes",
        "docker",
        "registry",
        "s3",
        "blob",
        "storage",
    }
)

# Sensitive / administrative hostnames → MEDIUM
_MEDIUM_NAMES = frozenset(
    {
        "secret",
        "backup",
        "prod-admin",
        "database",
        "db",
        "password",
        "credentials",
        "keys",
        "vault",
        "consul",
        "etcd",
        "zookeeper",
        "redis",
        "mongo",
        "mysql",
        "postgres",
        "elastic",
        "kibana-admin",
        "grafana-admin",
    }
)


def _classify_severity(name: str) -> Severity:
    """Determine severity based on the discovered asset name."""
    lower_name = name.lower().split(".")[0]

    if lower_name in _MEDIUM_NAMES:
        return Severity.MEDIUM

    if lower_name in _LOW_NAMES:
        return Severity.LOW

    return Severity.INFORMATIONAL


def parse_amass_json(output: str) -> list[Finding]:
    """Parse Amass stdout text (line-delimited JSON) into domain findings.

    Args:
        output: The raw stdout captured from an Amass enum scan.

    Returns:
        The findings parsed from the output (empty if there were none).
    """
    findings: list[Finding] = []

    for raw_line in output.splitlines():
        line = raw_line.strip()
        if not line:
            continue

        try:
            record = json.loads(line)
        except (json.JSONDecodeError, ValueError):
            _logger.debug("skipping malformed amass JSON line", line=line[:200])
            continue

        if not isinstance(record, dict):
            continue

        name = record.get("name", "")
        domain = record.get("domain", "")
        addresses = record.get("addresses", [])
        sources = record.get("sources", [])
        tag = record.get("tag", "")

        if not name:
            continue

        severity = _classify_severity(name)

        # Build address summary
        addr_parts = []
        for addr in addresses:
            ip = addr.get("ip", "")
            cidr = addr.get("cidr", "")
            if ip:
                addr_parts.append(ip)
            elif cidr:
                addr_parts.append(cidr)
        address_str = ", ".join(addr_parts) if addr_parts else "unknown"

        source_str = ", ".join(sources) if sources else "unknown"

        title = f"Subdomain: {name}"
        description = f"name: {name} | domain: {domain} | addresses: {address_str} | sources: {source_str} | tag: {tag}"

        finding = Finding.create(title=title, description=description, severity=severity)
        finding.add_evidence(
            Evidence(
                summary=f"Amass: {name} ({domain})",
                detail=f"name: {name} | domain: {domain} | addresses: {address_str} | sources: {source_str} | tag: {tag}",
                collected_at=datetime.now(UTC),
            )
        )
        findings.append(finding)

    return findings
