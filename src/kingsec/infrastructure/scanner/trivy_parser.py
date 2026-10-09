"""Parse Trivy JSON output into domain ``Finding`` objects.

Pure and side-effect-free: given raw stdout JSON from Trivy, produce domain
findings. Uses only the standard library (``json``). Trivy emits a JSON report
for a clean scan too, so malformed or structurally invalid output is reported
as a scanner failure instead of being indistinguishable from zero findings.

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

from kingsec.domain import Evidence, Finding, Recommendation, Severity
from kingsec.infrastructure.scanner.errors import ScannerOutputError

_OUTPUT_USER_MESSAGE = (
    "Trivy returned output in an unexpected format. Check the configured "
    "Trivy version and scan settings, then try again."
)

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


def _invalid_output(reason: str, *, cause: BaseException | None = None) -> ScannerOutputError:
    """Build a safe, consistently contextualized Trivy output error."""
    return ScannerOutputError(
        f"trivy output {reason}",
        context={"scanner": "trivy", "check_failed": reason},
        cause=cause,
        user_message=_OUTPUT_USER_MESSAGE,
    )


def _select_cvss(cvss: object) -> tuple[float | None, str | None]:
    """Pick one (score, vector) pair from Trivy's per-source CVSS dict.

    Within a chosen source, CVSS 3.1 is preferred over 4.0 when both are
    present (per reviewed decision) — 2.x is not considered: none of the
    scanners this session has actually observed used it, and adding
    handling for a version never seen in real output would be a guess, not
    a fix. A source with neither field present is skipped in favor of the
    next-preferred source rather than reported as a false zero.
    """
    if cvss is None:
        return None, None
    if not isinstance(cvss, dict):
        raise _invalid_output("contained a non-object CVSS field")
    for source in _CVSS_SOURCE_PREFERENCE:
        entry = cvss.get(source)
        if entry is None:
            continue
        if not isinstance(entry, dict):
            raise _invalid_output(f"contained a non-object CVSS entry for {source}")
        if entry.get("V3Score") is not None and entry.get("V3Vector"):
            try:
                return float(entry["V3Score"]), str(entry["V3Vector"])
            except (TypeError, ValueError) as exc:
                raise _invalid_output(f"contained an invalid CVSS 3 score for {source}", cause=exc) from exc
        if entry.get("V40Score") is not None and entry.get("V40Vector"):
            try:
                return float(entry["V40Score"]), str(entry["V40Vector"])
            except (TypeError, ValueError) as exc:
                raise _invalid_output(f"contained an invalid CVSS 4 score for {source}", cause=exc) from exc
    return None, None


def _parse_vulnerabilities(vulns: list[object], target: str) -> list[Finding]:
    """Parse the Vulnerabilities array from a Trivy result."""
    findings: list[Finding] = []

    for index, vuln in enumerate(vulns):
        if not isinstance(vuln, dict):
            raise _invalid_output(f"vulnerability at index {index} was not an object")

        vuln_id = vuln.get("VulnerabilityID", "")
        pkg_name = vuln.get("PkgName", "")
        installed = vuln.get("InstalledVersion", "")
        fixed = vuln.get("FixedVersion", "")
        severity_str = vuln.get("Severity", "UNKNOWN")
        title = vuln.get("Title", "")
        description = vuln.get("Description", "")
        cwe_values = vuln.get("CweIDs") or []
        string_fields = {
            "VulnerabilityID": vuln_id,
            "PkgName": pkg_name,
            "InstalledVersion": installed,
            "FixedVersion": fixed,
            "Severity": severity_str,
            "Title": title,
            "Description": description,
        }
        invalid_field = next((name for name, value in string_fields.items() if not isinstance(value, str)), None)
        if invalid_field is not None:
            raise _invalid_output(f"vulnerability at index {index} had a non-string '{invalid_field}' field")
        if not isinstance(cwe_values, list):
            raise _invalid_output(f"vulnerability at index {index} had a non-array 'CweIDs' field")
        cwe_ids = tuple(str(c) for c in cwe_values)
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


def _parse_misconfigs(misconfigs: list[object], target: str) -> list[Finding]:
    """Parse the Misconfigurations array from a Trivy result."""
    findings: list[Finding] = []

    for index, misconfig in enumerate(misconfigs):
        if not isinstance(misconfig, dict):
            raise _invalid_output(f"misconfiguration at index {index} was not an object")

        misconfig_id = misconfig.get("ID", "")
        severity_str = misconfig.get("Severity", "UNKNOWN")
        title = misconfig.get("Title", "")
        message = misconfig.get("Message", "")
        resolution = misconfig.get("Resolution", "")
        string_fields = {
            "ID": misconfig_id,
            "Severity": severity_str,
            "Title": title,
            "Message": message,
            "Resolution": resolution,
        }
        invalid_field = next((name for name, value in string_fields.items() if not isinstance(value, str)), None)
        if invalid_field is not None:
            raise _invalid_output(f"misconfiguration at index {index} had a non-string '{invalid_field}' field")

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
    if not output.strip():
        raise _invalid_output("was empty")

    try:
        data = json.loads(output)
    except (json.JSONDecodeError, ValueError) as exc:
        raise _invalid_output("was not valid JSON", cause=exc) from exc

    if not isinstance(data, dict):
        raise _invalid_output("did not contain a JSON object")

    if "Results" not in data:
        raise _invalid_output("was missing the 'Results' field")

    results = data["Results"]
    if not isinstance(results, list):
        raise _invalid_output("field 'Results' was not an array")

    findings: list[Finding] = []

    for index, result in enumerate(results):
        if not isinstance(result, dict):
            raise _invalid_output(f"result at index {index} was not an object")

        target = result.get("Target")
        if not isinstance(target, str) or not target:
            raise _invalid_output(f"result at index {index} had no valid 'Target'")

        vulns = result.get("Vulnerabilities", [])
        if not isinstance(vulns, list):
            raise _invalid_output(f"result at index {index} had a non-array 'Vulnerabilities' field")
        if vulns:
            findings.extend(_parse_vulnerabilities(vulns, target))

        misconfigs = result.get("Misconfigurations", [])
        if not isinstance(misconfigs, list):
            raise _invalid_output(f"result at index {index} had a non-array 'Misconfigurations' field")
        if misconfigs:
            findings.extend(_parse_misconfigs(misconfigs, target))

    return findings
