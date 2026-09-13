"""Parse ffuf JSONL output into domain ``Finding`` objects.

Pure and side-effect-free: given raw JSONL text from ``ffuf -json``, produce
domain findings. Uses only the standard library (``json``). Malformed or
incomplete lines are logged and skipped rather than failing the whole parse.

Base severity mapping (path/status only, before either demotion signal below):
    200/201          → LOW  (resource found — potential info disclosure)
    204              → INFORMATIONAL (empty response)
    301/302          → INFORMATIONAL (redirect)
    401/403          → MEDIUM (auth required / forbidden — access control)
    500+             → HIGH (server error — potential vulnerability)
    Interesting path → HIGH (.git, .env, .bak, .sql, id_rsa, .aws/credentials, ...)
    Admin/login path → MEDIUM

Phase 2B-c Priority 1b: a 200 on /.env returning 9KB of generic app HTML
used to score identically to a real leaked credentials file, because
severity came only from the URL string and status code
(docs/E2E-EVIDENCE-PHASE2B.md Defect 3). Two signals now demote (never
raise) severity when the response content contradicts the path-based
guess — see severity_demotion.py's module docstring for the full design
and downgrade-only rationale:

    Signal 1 (below): an interesting-path match whose Content-Type is
        HTML/markup is capped at LOW — real .env/.sql/.key/etc. files are
        essentially never legitimately served as text/html.
    Signal 2 (severity_demotion.compute_baseline_shape_demotions): among
        this batch's otherwise-MEDIUM-or-higher results, a (status,
        length) shape shared by a large cluster is capped at LOW —
        almost certainly one generic response repeated across many
        distinct paths, not that many distinct real findings.

A demotion is always recorded on the Finding (original_severity +
demotion_reason), never silent — see docs/STATUS.md.
"""

from __future__ import annotations

import json
import re
from datetime import UTC, datetime
from typing import Any

from kingsec.domain import Evidence, Finding, Severity, SeverityDemotionReason
from kingsec.infrastructure.logging import get_logger

from .severity_demotion import ShapeCandidate, compute_baseline_shape_demotions

_logger = get_logger("kingsec.infrastructure.scanner")

# File extensions that indicate sensitive data exposure.
_SENSITIVE_EXTENSIONS = frozenset(
    {
        ".git",
        ".env",
        ".bak",
        ".sql",
        ".zip",
        ".old",
        ".dump",
        ".log",
        ".conf",
        ".config",
        ".key",
        ".pem",
    }
)

# Phase 2B-c Priority 1b (approved plan): sensitive paths with no
# recognizable extension at all - named directly from the real flood in
# docs/E2E-EVIDENCE-PHASE2B.md Defect 3, Run 2, where a wildcard-responding
# target's every hit scored HIGH purely from these path fragments. Matched
# as path patterns, not extensions, per the approved plan's own wording.
_SENSITIVE_PATH_PATTERNS = (
    re.compile(r"\.git/head", re.IGNORECASE),
    re.compile(r"\.git/config", re.IGNORECASE),
    re.compile(r"(?:^|/)id_rsa(?:$|[/?#])", re.IGNORECASE),
    re.compile(r"\.aws/credentials", re.IGNORECASE),
    re.compile(r"(?:^|/)cosign\.key(?:$|[/?#])", re.IGNORECASE),
    re.compile(r"ws_ftp\.log", re.IGNORECASE),
)

# Path patterns that indicate admin/login areas.
_ADMIN_PATH_RE = re.compile(r"(admin|login|dashboard|manage|panel)", re.IGNORECASE)

# Content-types a real sensitive-path hit (.env, .sql, .key, id_rsa, ...)
# would never legitimately return - an HTML document at one of these paths
# is a generic app response, not a confirmed file disclosure (Signal 1).
_HTML_CONTENT_TYPES = frozenset({"text/html", "application/xhtml+xml"})


def _is_sensitive_path(url: str) -> bool:
    """True if ``url`` matches an interesting extension or path pattern."""
    lower_url = url.lower()
    if any(lower_url.endswith(ext) for ext in _SENSITIVE_EXTENSIONS):
        return True
    # Also match extensions in sub-paths (e.g., /backup/.git/config)
    # Use regex boundary check to avoid false positives like .gitignore matching .git
    for ext in _SENSITIVE_EXTENSIONS:
        ext_pattern = re.escape(ext) + r"(?:$|[/?#])"
        if re.search(ext_pattern, lower_url):
            return True
    return any(pattern.search(url) for pattern in _SENSITIVE_PATH_PATTERNS)


def _is_html_content_type(content_type: str) -> bool:
    """True if ``content_type`` is an HTML/markup type (ignoring any
    ``; charset=...`` suffix)."""
    return content_type.split(";", 1)[0].strip().lower() in _HTML_CONTENT_TYPES


def _base_severity(status: int, url: str) -> Severity:
    """Severity from path/status alone - what a reader relying only on the
    path name and HTTP status would conclude. Neither demotion signal
    reads this function's result as final; both only ever demote it."""
    if _is_sensitive_path(url):
        return Severity.HIGH
    if _ADMIN_PATH_RE.search(url):
        return Severity.MEDIUM

    if status >= 500:
        return Severity.HIGH
    if status in (401, 403):
        return Severity.MEDIUM
    if status in (200, 201):
        return Severity.LOW
    if status in (301, 302):
        return Severity.INFORMATIONAL
    if status == 204:
        return Severity.INFORMATIONAL

    return Severity.INFORMATIONAL


def _safe_length(value: Any) -> int:
    """Coerce ffuf's ``length`` field to an int for shape-clustering keys;
    a malformed/missing value groups with other malformed values rather
    than crashing the parse (evidence text still shows the raw value)."""
    return value if isinstance(value, int) else 0


def parse_ffuf_json(output: str) -> list[Finding]:
    """Parse ffuf JSONL stdout into domain findings.

    Args:
        output: The raw stdout captured from a ffuf run with ``-json``.

    Returns:
        The findings parsed from the output (empty if there were none).
    """
    records: list[dict[str, Any]] = []

    for line in output.splitlines():
        stripped = line.strip()
        if not stripped:
            continue

        try:
            record = json.loads(stripped)
        except json.JSONDecodeError:
            _logger.warning("skipping non-JSON ffuf output line")
            continue

        if not isinstance(record, dict):
            continue

        # Skip the final summary line (has "results" key instead of "input")
        if "results" in record:
            continue

        status = record.get("status", 0)
        if not isinstance(status, int):
            continue

        url = record.get("url", "")
        input_val = record.get("input", {})
        fuzz_value = input_val.get("FUZZ", "") if isinstance(input_val, dict) else ""
        content_type = record.get("content-type", "")
        records.append(
            {
                "status": status,
                "url": url,
                "fuzz_value": fuzz_value,
                "length": record.get("length", 0),
                "words": record.get("words", 0),
                "lines_count": record.get("lines", 0),
                "content_type": content_type if isinstance(content_type, str) else "",
                "duration": record.get("duration", 0),
            }
        )

    base_severities = [_base_severity(r["status"], r["url"]) for r in records]

    # Signal 1: content-type mismatch on an otherwise-sensitive-path hit.
    signal1_demoted = [
        _is_sensitive_path(r["url"]) and _is_html_content_type(r["content_type"]) for r in records
    ]

    # Signal 2: baseline-shape clustering, restricted to results that would
    # otherwise score MEDIUM or higher (per-record base classification,
    # never the already-demoted severity).
    candidates = [
        ShapeCandidate(index=i, status=r["status"], length=_safe_length(r["length"]), base_severity=base_severities[i])
        for i, r in enumerate(records)
        if base_severities[i] >= Severity.MEDIUM
    ]
    signal2_demoted = compute_baseline_shape_demotions(candidates, total_results=len(records))

    findings: list[Finding] = []
    for i, r in enumerate(records):
        base = base_severities[i]
        if signal1_demoted[i]:
            severity, original_severity, demotion_reason = (
                Severity.LOW,
                base,
                SeverityDemotionReason.CONTENT_TYPE_MISMATCH,
            )
        elif i in signal2_demoted:
            severity, original_severity, demotion_reason = (
                Severity.LOW,
                base,
                SeverityDemotionReason.BASELINE_SHAPE_MATCH,
            )
        else:
            severity, original_severity, demotion_reason = base, None, None

        status, url = r["status"], r["url"]
        length, words, lines_count, fuzz_value = r["length"], r["words"], r["lines_count"], r["fuzz_value"]
        content_type, duration = r["content_type"], r["duration"]

        title = f"HTTP {status} — {url}"
        description = (
            f"Status: {status} | Length: {length} | Words: {words} | Lines: {lines_count} | Fuzz: {fuzz_value}"
        )

        finding = Finding.create(
            title=title,
            description=description,
            severity=severity,
            original_severity=original_severity,
            demotion_reason=demotion_reason,
        )
        finding.add_evidence(
            Evidence(
                summary=f"ffuf: {status} {url}",
                detail=(
                    f"status: {status} | url: {url} | length: {length} | "
                    f"words: {words} | lines: {lines_count} | "
                    f"content-type: {content_type} | duration: {duration}us"
                ),
                collected_at=datetime.now(UTC),
            )
        )
        findings.append(finding)

    return findings
