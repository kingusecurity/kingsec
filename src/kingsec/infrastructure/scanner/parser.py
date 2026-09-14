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
from datetime import UTC, datetime
from typing import Any

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


def _coerce_cvss_score(value: object) -> float | None:
    """Nuclei's cvss-score is normally a float, but JSON/YAML round-tripping
    can leave it as a string or int - coerce defensively rather than letting
    a shape surprise from one template break the whole scan's parse."""
    if value is None:
        return None
    try:
        score = float(value)  # type: ignore[arg-type]
    except (TypeError, ValueError):
        return None
    if not (0.0 <= score <= 10.0):
        return None
    return score


def _extract_str_list(value: object) -> list[str]:
    """Normalise a field that may be a single string, a list of strings, or None."""
    if isinstance(value, list):
        return [str(v) for v in value]
    if isinstance(value, str):
        return [value]
    return []


def _record_key(record: dict[str, Any]) -> tuple[str, str]:
    """Group key for collapsing Nuclei records into one Finding.

    Phase 2C Step 2 GAP fix 5: a template with ``matchers-condition: or`` and
    several NAMED matchers (e.g. ``http-missing-security-headers``, which
    checks ~12 individual HTTP headers as separate matchers) makes Nuclei
    emit one JSONL record PER MATCHED MATCHER against the same URL, not one
    per logical finding - confirmed against the real cached template
    (nuclei-templates/http/misconfiguration/http-missing-security-headers.yaml)
    and the real persisted evidence, which showed 10 byte-identical-looking
    records (same title/description/matched-at/template-id) for one DVWA
    login page. ``title``/``severity``/CVE/CWE all come from the template's
    single ``info:`` block, so they are always identical across every
    matcher of the same template - grouping by (template-id, matched-at)
    can never incorrectly merge two genuinely different findings. The
    overwhelming majority of templates only ever produce one record per
    matched-at, so this grouping is a no-op for them.
    """
    template_id = record.get("template-id") or record.get("templateID") or ""
    matched_at = record.get("matched-at") or record.get("host") or "unknown"
    return (str(template_id), str(matched_at))


def _finding_from_group(records: list[dict[str, Any]]) -> Finding | None:
    """Build one Finding from a group of Nuclei records sharing the same
    (template-id, matched-at) - almost always a single record.

    When there is more than one (a multi-matcher "or" template - e.g. one
    record per missing HTTP header), the group collapses into ONE finding:
    the matcher names are listed in the finding's own description so the
    reader doesn't have to open every evidence block to see what matched,
    and each record still contributes its own Evidence entry (naming its
    matcher) so no individual match's detail is lost.

    Returns None (and logs) if the group lacks the minimum fields needed to
    be a meaningful finding.
    """
    primary = records[0]
    template_id = primary.get("template-id") or primary.get("templateID")
    info = primary.get("info") or {}
    name = info.get("name") or template_id
    if not name:
        _logger.warning("skipping nuclei record without name or template-id")
        return None

    severity = _map_severity(info.get("severity"))
    description = info.get("description") or f"Matched by template '{template_id}'."

    # Extract CVE / CWE identifiers and CVSS score/vector from classification.
    # Nuclei populates this block from the template's own `info.classification`
    # metadata for CVE-tagged templates - it's not present for every template
    # (e.g. tech-detection, exposed-panel templates carry no CVE), so every
    # field here is genuinely optional.
    classification = info.get("classification") or {}
    cve_ids = tuple(_extract_str_list(classification.get("cve-id")))
    cwe_ids = tuple(_extract_str_list(classification.get("cwe-id")))
    cvss_score = _coerce_cvss_score(classification.get("cvss-score"))
    cvss_vector = classification.get("cvss-metrics") or None
    extra = []
    if cve_ids:
        extra.append(f"CVE: {', '.join(cve_ids)}")
    if cwe_ids:
        extra.append(f"CWE: {', '.join(cwe_ids)}")
    if extra:
        description = f"{description} ({'; '.join(extra)})"

    matcher_names = [str(r["matcher-name"]) for r in records if r.get("matcher-name")]
    if len(records) > 1 and matcher_names:
        description = f"{description} Matched checks: {', '.join(matcher_names)}."

    finding = Finding.create(
        title=str(name),
        description=str(description),
        severity=severity,
        cve_ids=cve_ids,
        cwe_ids=cwe_ids,
        cvss_score=cvss_score,
        cvss_vector=cvss_vector,
    )

    # Evidence: where and how it matched, one entry per underlying record so
    # a collapsed multi-matcher group still shows every individual match.
    references = _extract_str_list(info.get("references"))
    for record in records:
        matched_at = record.get("matched-at") or record.get("host") or "unknown"
        detail_parts = [f"matched-at: {matched_at}"]
        if record.get("type"):
            detail_parts.append(f"type: {record['type']}")
        if template_id:
            detail_parts.append(f"template-id: {template_id}")
        if record.get("matcher-name"):
            detail_parts.append(f"matcher: {record['matcher-name']}")
        if cve_ids:
            detail_parts.append(f"cve: {', '.join(cve_ids)}")
        if cwe_ids:
            detail_parts.append(f"cwe: {', '.join(cwe_ids)}")
        if references:
            detail_parts.append(f"references: {' '.join(references)}")

        summary = f"Matched by Nuclei template '{template_id or name}'"
        if record.get("matcher-name"):
            summary = f"{summary} (matcher: {record['matcher-name']})"

        finding.add_evidence(
            Evidence(
                summary=summary,
                detail=" | ".join(detail_parts),
                collected_at=datetime.now(UTC),
            )
        )

    # Optional remediation -> a domain Recommendation. Template-level field
    # (declared once in info:), so identical across every record in the
    # group - reading it from the primary record only is correct, not a
    # simplification that drops distinct data.
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

    Records are grouped by (template-id, matched-at) before building
    findings - see ``_record_key``'s docstring for why that grouping is
    always safe and when it actually collapses more than one record.

    Args:
        output: The raw stdout captured from a Nuclei run (JSON-lines).

    Returns:
        The findings parsed from the output (empty if there were none).
    """
    groups: dict[tuple[str, str], list[dict[str, Any]]] = {}
    order: list[tuple[str, str]] = []
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
        key = _record_key(record)
        if key not in groups:
            groups[key] = []
            order.append(key)
        groups[key].append(record)

    findings: list[Finding] = []
    for key in order:
        finding = _finding_from_group(groups[key])
        if finding is not None:
            findings.append(finding)
    return findings
