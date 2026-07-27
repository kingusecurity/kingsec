"""Parse ffuf JSONL output into domain ``Finding`` objects.

Pure and side-effect-free: given raw JSONL text from ``ffuf -json``, produce
domain findings. Uses only the standard library (``json``). Malformed or
incomplete lines are logged and skipped rather than failing the whole parse.

Severity mapping (conservative):
    200/201          → LOW  (resource found — potential info disclosure)
    204              → INFORMATIONAL (empty response)
    301/302          → INFORMATIONAL (redirect)
    401/403          → MEDIUM (auth required / forbidden — access control)
    500+             → HIGH (server error — potential vulnerability)
    Interesting ext  → HIGH (.git, .env, .bak, .sql, .zip, .old)
    Admin/login path → MEDIUM
"""

from __future__ import annotations

import json
import re
from datetime import UTC, datetime

from kingsec.domain import Evidence, Finding, Severity
from kingsec.infrastructure.logging import get_logger

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

# Path patterns that indicate admin/login areas.
_ADMIN_PATH_RE = re.compile(r"(admin|login|dashboard|manage|panel)", re.IGNORECASE)


def _classify_severity(status: int, url: str) -> Severity:
    """Determine severity based on HTTP status code and URL path."""
    # Interesting file extensions → HIGH
    lower_url = url.lower()
    if any(lower_url.endswith(ext) for ext in _SENSITIVE_EXTENSIONS):
        return Severity.HIGH
    # Also match extensions in sub-paths (e.g., /backup/.git/config)
    # Use regex boundary check to avoid false positives like .gitignore matching .git
    for ext in _SENSITIVE_EXTENSIONS:
        ext_pattern = re.escape(ext) + r"(?:$|[/?#])"
        if re.search(ext_pattern, lower_url):
            return Severity.HIGH

    # Admin/login paths → MEDIUM
    if _ADMIN_PATH_RE.search(url):
        return Severity.MEDIUM

    # Status code classification
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


def parse_ffuf_json(output: str) -> list[Finding]:
    """Parse ffuf JSONL stdout into domain findings.

    Args:
        output: The raw stdout captured from a ffuf run with ``-json``.

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
        length = record.get("length", 0)
        words = record.get("words", 0)
        lines_count = record.get("lines", 0)
        content_type = record.get("content-type", "")
        duration = record.get("duration", 0)

        severity = _classify_severity(status, url)

        title = f"HTTP {status} — {url}"
        description = (
            f"Status: {status} | Length: {length} | Words: {words} | Lines: {lines_count} | Fuzz: {fuzz_value}"
        )

        finding = Finding.create(title=title, description=description, severity=severity)
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
