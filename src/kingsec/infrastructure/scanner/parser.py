"""Parse Nuclei JSONL output into domain ``Finding`` objects.

Pure and side-effect-free (apart from logging a skipped malformed line): given
the raw stdout text, produce domain findings. Keeping this separate from process
execution makes it trivially unit-testable with canned fixtures.

Resilience policy: Nuclei emits one JSON object per line with ``-jsonl``. A
single malformed or field-incomplete line is logged and SKIPPED rather than
failing the whole scan — one odd line should not discard a hundred valid
findings. Empty output means "no findings", which is a valid, successful result.
"""

from __future__ import annotations

import json
from datetime import datetime, timezone

from kingsec.domain import Evidence, Finding, Recommendation, Severity
from kingsec.infrastructure.logging import get_logger

_logger = get_logger("kingsec.infrastructure.scanner")

# Nuclei severity strings -> domain Severity. Unknown/absent maps to the lowest.
_SEVERITY_MAP: dict[str, Severity] = {
    "info": Severity.INFORMATIONAL,
    "informational": Severity.INFORMATIONAL,
    "low": Severity.LOW,
    "medium": Severity.MEDIUM,
    "high": Severity.HIGH,
    "critical": Severity.CRITICAL,
}


def _map_severity(raw: str | None) -> Severity:
    return _SEVERITY_MAP.get((raw or "").strip().lower(), Severity.INFORMATIONAL)


def _finding_from_record(record: dict) -> Finding | None:
    """Build a single Finding from one parsed Nuclei JSON record, or None.

    Returns None (and logs) if the record lacks the minimum fields needed to be
    a meaningful finding.
    """

    template_id = record.get("template-id") or record.get("templateID")
    info = record.get("info") or {}
    name = info.get("name") or template_id
    if not name:
        _logger.warning("skipping nuclei record without name or template-id")
        return None

    severity = _map_severity(info.get("severity"))
    description = info.get("description") or f"Matched by template '{template_id}'."

    finding = Finding.create(title=str(name), description=str(description), severity=severity)

    # Evidence: where and how it matched. matched-at is the concrete locator.
    matched_at = record.get("matched-at") or record.get("host") or "unknown"
    detail_parts = [f"matched-at: {matched_at}"]
    if record.get("type"):
        detail_parts.append(f"type: {record['type']}")
    if template_id:
        detail_parts.append(f"template-id: {template_id}")
    finding.add_evidence(
        Evidence(
            summary=f"Matched by Nuclei template '{template_id or name}'",
            detail=" | ".join(detail_parts),
            collected_at=datetime.now(timezone.utc),
        )
    )

    # Optional remediation -> a domain Recommendation.
    remediation = info.get("remediation")
    if remediation:
        finding.add_recommendation(
            Recommendation(
                title="Remediation",
                description=str(remediation),
                priority=severity,
            )
        )

    return finding


def parse_nuclei_jsonl(output: str) -> list[Finding]:
    """Parse Nuclei JSONL stdout into domain findings.

    Args:
        output: The raw stdout captured from a Nuclei run (JSON-lines).

    Returns:
        The findings parsed from the output (empty if there were none).
    """

    findings: list[Finding] = []
    for line in output.splitlines():
        stripped = line.strip()
        if not stripped:
            continue
        try:
            record = json.loads(stripped)
        except json.JSONDecodeError:
            # A non-JSON line (banner, stray log) — skip it, keep the rest.
            _logger.warning("skipping non-JSON nuclei output line")
            continue
        if not isinstance(record, dict):
            _logger.warning("skipping non-object nuclei output line")
            continue
        finding = _finding_from_record(record)
        if finding is not None:
            findings.append(finding)
    return findings
