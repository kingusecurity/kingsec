"""Parse Trivy JSON output into domain ``Finding`` objects.

Pure and side-effect-free: given raw stdout JSON from Trivy, produce
domain findings. Uses only the standard library (``json``). Malformed or
incomplete records are logged and skipped rather than failing the whole parse.

Trivy JSON output structure:
    Top-level dict with ``Results`` array. Each result contains:
    ``Target``, ``Class`` (os-pkgs, lang-pkgs, config), and either
    ``Vulnerabilities`` or ``Misconfigurations`` arrays.

Severity mapping:
    CRITICAL → CRITICAL
    HIGH     → HIGH
    MEDIUM   → MEDIUM
    LOW      → LOW
    UNKNOWN  → INFORMATIONAL
"""

from __future__ import annotations

import json
from datetime import UTC, datetime
from typing import Any

from kingsec.domain import Evidence, Finding, Recommendation, Severity
from kingsec.infrastructure.logging import get_logger

_logger = get_logger("kingsec.infrastructure.scanner")

_SEVERITY_MAP = {
    "CRITICAL": Severity.CRITICAL,
    "HIGH": Severity.HIGH,
    "MEDIUM": Severity.MEDIUM,
    "LOW": Severity.LOW,
    "UNKNOWN": Severity.INFORMATIONAL,
}


def _map_severity(trivy_severity: str) -> Severity:
    """Map Trivy severity string to domain Severity."""
    return _SEVERITY_MAP.get(trivy_severity.upper(), Severity.INFORMATIONAL)


# Trivy reports CVSS from multiple vendor sources for the same CVE, which can
# genuinely disagree (e.g. the same CVE scored 6.1 by one source and 5.4 by
# another). Deterministic, single-value-per-finding for this pass, per
# reviewed decision: NVD > RedHat > GHSA. Surfacing real cross-source
# disagreement to the reader is a future enhancement, not this one.
_CVSS_SOURCE_PREFERENCE = ("nvd", "redhat", "ghsa")


def _select_cvss(cvss: object) -> tuple[float | None, str | None]:
    """Pick one (score, vector) pair from Trivy's per-source CVSS dict.

    Within a chosen source, CVSS 3.1 is preferred over 4.0 when both are
    present (per reviewed decision) — 2.x is not considered: none of the
    scanners this session has actually observed used it, and adding
    handling for a version never seen in real output would be a guess, not
    a fix. A source with neither field present is skipped in favor of the
    next-preferred source rather than reported as a false zero.
    """
    if not isinstance(cvss, dict):
        return None, None
    for source in _CVSS_SOURCE_PREFERENCE:
        entry = cvss.get(source)
        if not isinstance(entry, dict):
            continue
        if entry.get("V3Score") is not None and entry.get("V3Vector"):
            return float(entry["V3Score"]), str(entry["V3Vector"])
        if entry.get("V40Score") is not None and entry.get("V40Vector"):
            return float(entry["V40Score"]), str(entry["V40Vector"])
    return None, None


def _parse_vulnerabilities(vulns: list[dict[str, Any]], target: str) -> list[Finding]:
    """Parse the Vulnerabilities array from a Trivy result."""
    findings: list[Finding] = []

    for vuln in vulns:
        vuln_id = vuln.get("VulnerabilityID", "")
        pkg_name = vuln.get("PkgName", "")
        installed = vuln.get("InstalledVersion", "")
        fixed = vuln.get("FixedVersion", "")
        severity_str = vuln.get("Severity", "UNKNOWN")
        title = vuln.get("Title", "")
        description = vuln.get("Description", "")
        cwe_ids = tuple(str(c) for c in (vuln.get("CweIDs") or []))
        cvss_score, cvss_vector = _select_cvss(vuln.get("CVSS"))

        severity = _map_severity(severity_str)

        finding_title = f"{vuln_id} — {pkg_name}"
        finding_desc = (
            f"vuln: {vuln_id} | pkg: {pkg_name} | installed: {installed} | "
            f"fixed: {fixed or 'none'} | severity: {severity_str} | target: {target}"
        )
        if title:
            finding_desc += f" | title: {title}"

        finding = Finding.create(
            title=finding_title,
            description=finding_desc,
            severity=severity,
            cve_ids=(vuln_id,) if vuln_id else (),
            cwe_ids=cwe_ids,
            cvss_score=cvss_score,
            cvss_vector=cvss_vector,
        )
        finding.add_evidence(
            Evidence(
                summary=f"Trivy: {vuln_id} in {pkg_name}",
                detail=(
                    f"vuln: {vuln_id} | pkg: {pkg_name} | installed: {installed} | "
                    f"fixed: {fixed or 'none'} | severity: {severity_str} | "
                    f"title: {title} | description: {description[:200]}"
                ),
                collected_at=datetime.now(UTC),
            )
        )
        findings.append(finding)

    return findings


def _parse_misconfigs(misconfigs: list[dict[str, Any]], target: str) -> list[Finding]:
    """Parse the Misconfigurations array from a Trivy result."""
    findings: list[Finding] = []

    for misconfig in misconfigs:
        misconfig_id = misconfig.get("ID", "")
        severity_str = misconfig.get("Severity", "UNKNOWN")
        title = misconfig.get("Title", "")
        message = misconfig.get("Message", "")
        resolution = misconfig.get("Resolution", "")

        severity = _map_severity(severity_str)

        finding_title = f"{misconfig_id} — {title}" if title else misconfig_id
        finding_desc = f"misconfig: {misconfig_id} | severity: {severity_str} | target: {target}"
        if message:
            finding_desc += f" | message: {message[:200]}"

        finding = Finding.create(
            title=finding_title,
            description=finding_desc,
            severity=severity,
        )
        finding.add_evidence(
            Evidence(
                summary=f"Trivy misconfig: {misconfig_id}",
                detail=(
                    f"misconfig: {misconfig_id} | severity: {severity_str} | "
                    f"title: {title} | message: {message[:200]} | "
                    f"resolution: {resolution[:200]}"
                ),
                collected_at=datetime.now(UTC),
            )
        )
        if resolution:
            finding.add_recommendation(
                Recommendation(
                    title="Remediation",
                    description=str(resolution),
                    priority=severity,
                )
            )
        findings.append(finding)

    return findings


def parse_trivy_json(output: str) -> list[Finding]:
    """Parse Trivy stdout JSON into domain findings.

    Args:
        output: The raw stdout JSON captured from a Trivy scan.

    Returns:
        The findings parsed from the output (empty if there were none).
    """
    try:
        data = json.loads(output)
    except (json.JSONDecodeError, ValueError):
        _logger.debug("failed to parse trivy JSON output")
        return []

    if not isinstance(data, dict):
        return []

    results = data.get("Results", [])
    if not isinstance(results, list):
        return []

    findings: list[Finding] = []

    for result in results:
        if not isinstance(result, dict):
            continue

        target = result.get("Target", "")

        vulns = result.get("Vulnerabilities", [])
        if isinstance(vulns, list) and vulns:
            findings.extend(_parse_vulnerabilities(vulns, target))

        misconfigs = result.get("Misconfigurations", [])
        if isinstance(misconfigs, list) and misconfigs:
            findings.extend(_parse_misconfigs(misconfigs, target))

    return findings
