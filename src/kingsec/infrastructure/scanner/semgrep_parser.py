"""Parse Semgrep JSON output into domain ``Finding`` objects.

Pure and side-effect-free: given raw stdout JSON from Semgrep, produce
domain findings. Uses only the standard library (``json``). Malformed or
incomplete records are logged and skipped rather than failing the whole parse.

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
from kingsec.infrastructure.logging import get_logger

_logger = get_logger("kingsec.infrastructure.scanner")

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


def parse_semgrep_json(output: str) -> list[Finding]:
    """Parse Semgrep stdout JSON into domain findings.

    Args:
        output: The raw stdout JSON captured from a Semgrep scan.

    Returns:
        The findings parsed from the output (empty if there were none).
    """
    try:
        data = json.loads(output)
    except (json.JSONDecodeError, ValueError):
        _logger.debug("failed to parse semgrep JSON output")
        return []

    if not isinstance(data, dict):
        return []

    results = data.get("results", [])
    if not isinstance(results, list):
        return []

    findings: list[Finding] = []

    for result in results:
        if not isinstance(result, dict):
            continue

        check_id = result.get("check_id", "")
        path = result.get("path", "")
        start = result.get("start", {})
        end = result.get("end", {})
        extra = result.get("extra", {})

        message = extra.get("message", "")
        severity_str = extra.get("severity", "INFO")
        metadata = extra.get("metadata", {})

        severity = _map_severity(severity_str)

        start_line = start.get("line", "?") if isinstance(start, dict) else "?"
        end_line = end.get("line", "?") if isinstance(end, dict) else "?"

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
        category = metadata.get("category", "") if isinstance(metadata, dict) else ""
        confidence = metadata.get("confidence", "") if isinstance(metadata, dict) else ""

        # Extract CVE / CWE / references from metadata
        cve_ids = _extract_str_list(metadata.get("cve", "")) if isinstance(metadata, dict) else []
        cwe_ids = _extract_str_list(metadata.get("cwe", "")) if isinstance(metadata, dict) else []
        refs = _extract_str_list(metadata.get("references", "")) if isinstance(metadata, dict) else []

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
        fix = extra.get("fix", "") if isinstance(extra, dict) else ""
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
