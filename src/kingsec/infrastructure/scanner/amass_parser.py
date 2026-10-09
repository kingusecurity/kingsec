"""Parse OWASP Amass JSON output into domain ``Finding`` objects.

Pure and side-effect-free: given raw stdout text from Amass, produce domain
findings. Uses only the standard library (``json``). Blank output is a valid
clean enumeration; once a nonblank JSONL record is present, malformed or
structurally invalid data is a scanner-output failure rather than something to
silently discard.

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
from kingsec.infrastructure.scanner.errors import ScannerOutputError

_OUTPUT_USER_MESSAGE = (
    "Amass returned output in an unexpected format. Check the configured "
    "Amass version and scan settings, then try again."
)

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


def _invalid_output(reason: str, *, cause: BaseException | None = None) -> ScannerOutputError:
    """Build a safe, consistently contextualized Amass output error."""
    return ScannerOutputError(
        f"amass output {reason}",
        context={"scanner": "amass", "check_failed": reason},
        cause=cause,
        user_message=_OUTPUT_USER_MESSAGE,
    )


def parse_amass_json(output: str) -> list[Finding]:
    """Parse Amass stdout text (line-delimited JSON) into domain findings.

    Args:
        output: The raw stdout captured from an Amass enum scan.

    Returns:
        The findings parsed from the output (empty if there were none).
    """
    findings: list[Finding] = []

    for line_number, raw_line in enumerate(output.splitlines(), start=1):
        line = raw_line.strip()
        if not line:
            continue

        try:
            record = json.loads(line)
        except (json.JSONDecodeError, ValueError) as exc:
            raise _invalid_output(f"line {line_number} was not valid JSON", cause=exc) from exc

        if not isinstance(record, dict):
            raise _invalid_output(f"line {line_number} was not a JSON object")

        name = record.get("name")
        domain = record.get("domain", "")
        addresses = record.get("addresses", [])
        sources = record.get("sources", [])
        tag = record.get("tag", "")

        if not isinstance(name, str) or not name:
            raise _invalid_output(f"line {line_number} had no valid 'name'")
        if not isinstance(domain, str):
            raise _invalid_output(f"line {line_number} had a non-string 'domain'")
        if not isinstance(addresses, list):
            raise _invalid_output(f"line {line_number} had a non-array 'addresses' field")
        if not isinstance(sources, list) or any(not isinstance(source, str) for source in sources):
            raise _invalid_output(f"line {line_number} had an invalid 'sources' field")
        if not isinstance(tag, str):
            raise _invalid_output(f"line {line_number} had a non-string 'tag'")

        severity = _classify_severity(name)

        # Build address summary
        addr_parts = []
        for address_index, addr in enumerate(addresses):
            if not isinstance(addr, dict):
                raise _invalid_output(
                    f"line {line_number} address at index {address_index} was not an object"
                )
            ip = addr.get("ip", "")
            cidr = addr.get("cidr", "")
            if not isinstance(ip, str) or not isinstance(cidr, str):
                raise _invalid_output(
                    f"line {line_number} address at index {address_index} had invalid fields"
                )
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
