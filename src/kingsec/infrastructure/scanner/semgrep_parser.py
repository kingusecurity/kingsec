"""Parse Semgrep JSON output into domain ``Finding`` objects.

Pure and side-effect-free: given raw stdout JSON from Semgrep, produce
domain findings. Uses only the standard library (``json``). A successful
Semgrep invocation always emits a JSON report, including for a clean scan, so
missing or structurally invalid report data is a scanner-output failure rather
than an apparent zero-finding success.

Semgrep JSON output structure:
    Top-level dict with ``results`` array. Each result contains:
    ``check_id``, ``path``, ``start`` (line/col), ``end`` (line/col),
    ``extra`` dict with ``message``, ``severity``, ``metadata``.

Severity mapping:
    ERROR   → HIGH
    WARNING → MEDIUM
    INFO    → LOW
"""

from __future__ import annotations

import json
from datetime import UTC, datetime

from kingsec.domain import Evidence, Finding, Recommendation, Severity
from kingsec.infrastructure.scanner.errors import ScannerOutputError

_OUTPUT_USER_MESSAGE = (
    "Semgrep returned output in an unexpected format. Check the configured "
    "Semgrep version and scan settings, then try again."
)

_SEVERITY_MAP = {
    "ERROR": Severity.HIGH,
    "WARNING": Severity.MEDIUM,
    "INFO": Severity.LOW,
}


def _map_severity(semgrep_severity: str) -> Severity:
    """Map Semgrep severity string to domain Severity."""
    return _SEVERITY_MAP.get(semgrep_severity.upper(), Severity.LOW)


def _extract_str_list(value: object) -> list[str]:
    """Normalise a field that may be a single string, a list of strings, or empty."""
    if isinstance(value, list):
        return [str(v) for v in value]
    if isinstance(value, str) and value:
        return [value]
    return []


def _invalid_output(reason: str, *, cause: BaseException | None = None) -> ScannerOutputError:
    """Build a safe, consistently contextualized Semgrep output error."""
    return ScannerOutputError(
        f"semgrep output {reason}",
        context={"scanner": "semgrep", "check_failed": reason},
        cause=cause,
        user_message=_OUTPUT_USER_MESSAGE,
    )


def parse_semgrep_json(output: str) -> list[Finding]:
    """Parse Semgrep stdout JSON into domain findings.

    Args:
        output: The raw stdout JSON captured from a Semgrep scan.

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

    if "results" not in data:
        raise _invalid_output("was missing the 'results' field")

    results = data["results"]
    if not isinstance(results, list):
        raise _invalid_output("field 'results' was not an array")

    findings: list[Finding] = []

    for index, result in enumerate(results):
        if not isinstance(result, dict):
            raise _invalid_output(f"result at index {index} was not an object")

        check_id = result.get("check_id")
        path = result.get("path")
        start = result.get("start")
        end = result.get("end")
        extra = result.get("extra")

        if not isinstance(check_id, str) or not check_id:
            raise _invalid_output(f"result at index {index} had no valid 'check_id'")
        if not isinstance(path, str) or not path:
            raise _invalid_output(f"result at index {index} had no valid 'path'")
        if not isinstance(start, dict) or not isinstance(start.get("line"), int):
            raise _invalid_output(f"result at index {index} had no valid start line")
        if not isinstance(end, dict) or not isinstance(end.get("line"), int):
            raise _invalid_output(f"result at index {index} had no valid end line")
        if not isinstance(extra, dict):
            raise _invalid_output(f"result at index {index} had no valid 'extra' object")

        message = extra.get("message", "")
        severity_str = extra.get("severity", "INFO")
        metadata = extra.get("metadata", {})

        if not isinstance(message, str):
            raise _invalid_output(f"result at index {index} had a non-string message")
        if not isinstance(severity_str, str):
            raise _invalid_output(f"result at index {index} had a non-string severity")
        if not isinstance(metadata, dict):
            raise _invalid_output(f"result at index {index} had a non-object metadata field")

        severity = _map_severity(severity_str)

        start_line = start["line"]
        end_line = end["line"]

        title = f"{check_id} — {path}"
        description_parts = [
            f"rule: {check_id}",
            f"file: {path}",
            f"lines: {start_line}-{end_line}",
            f"severity: {severity_str}",
        ]
        if message:
            description_parts.append(f"message: {message[:200]}")
        description = " | ".join(description_parts)

        # Extract metadata fields
        category = metadata.get("category", "")
        confidence = metadata.get("confidence", "")

        # Extract CVE / CWE / references from metadata
        cve_ids = _extract_str_list(metadata.get("cve", ""))
        cwe_ids = _extract_str_list(metadata.get("cwe", ""))
        refs = _extract_str_list(metadata.get("references", ""))

        # Append CVE/CWE to description
        extra_desc = []
        if cve_ids:
            extra_desc.append(f"CVE: {', '.join(cve_ids)}")
        if cwe_ids:
            extra_desc.append(f"CWE: {', '.join(cwe_ids)}")
        if extra_desc:
            description += f" ({'; '.join(extra_desc)})"

        finding = Finding.create(
            title=title,
            description=description,
            severity=severity,
        )

        detail = (
            f"rule: {check_id} | file: {path} | lines: {start_line}-{end_line} | "
            f"severity: {severity_str} | message: {message[:200]} | "
            f"category: {category} | confidence: {confidence}"
        )
        if cve_ids:
            detail += f" | cve: {', '.join(cve_ids)}"
        if cwe_ids:
            detail += f" | cwe: {', '.join(cwe_ids)}"
        if refs:
            detail += f" | references: {' '.join(refs)}"

        finding.add_evidence(
            Evidence(
                summary=f"Semgrep: {check_id}",
                detail=detail,
                collected_at=datetime.now(UTC),
            )
        )

        # Optional fix → Recommendation
        fix = extra.get("fix", "")
        if not isinstance(fix, str):
            raise _invalid_output(f"result at index {index} had a non-string fix")
        if fix:
            finding.add_recommendation(
                Recommendation(
                    title="Remediation",
                    description=str(fix),
                    priority=severity,
                )
            )
        findings.append(finding)

    return findings
