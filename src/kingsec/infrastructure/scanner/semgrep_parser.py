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

from kingsec.domain import Evidence, Finding, Severity
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

        finding = Finding.create(
            title=title,
            description=description,
            severity=severity,
        )
        finding.add_evidence(
            Evidence(
                summary=f"Semgrep: {check_id}",
                detail=(
                    f"rule: {check_id} | file: {path} | lines: {start_line}-{end_line} | "
                    f"severity: {severity_str} | message: {message[:200]} | "
                    f"category: {category} | confidence: {confidence}"
                ),
                collected_at=datetime.now(UTC),
            )
        )
        findings.append(finding)

    return findings
