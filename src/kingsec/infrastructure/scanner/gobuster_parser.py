"""Parse Gobuster directory enumeration output into domain ``Finding`` objects.

Pure and side-effect-free: given raw stdout text from Gobuster, produce
domain findings. Uses only the standard library (``re``). Malformed or
incomplete lines are logged and skipped rather than failing the whole parse.

Gobuster output format (directory mode):
    Lines containing ``(Status: NNN) [Size: NNN]`` are findings.
    Separator lines (``===``) and metadata lines are skipped.

Severity mapping (conservative):
    200/201/204       → LOW  (resource found)
    301/302           → INFORMATIONAL (redirect)
    401/403           → MEDIUM (auth required / forbidden)
    500+              → HIGH (server error)
    Interesting paths → HIGH or MEDIUM based on sensitivity
"""

from __future__ import annotations

import re
from datetime import datetime, timezone

from kingsec.domain import Evidence, Finding, Severity
from kingsec.infrastructure.logging import get_logger

_logger = get_logger("kingsec.infrastructure.scanner")

# Pattern: /path                 (Status: 200) [Size: 1234]
_FINDING_RE = re.compile(
    r"^\s*(\S+)\s+\(Status:\s*(\d+)\)\s+\[Size:\s*(\d+)\]"
)

# Sensitive paths → HIGH
_SENSITIVE_PATHS = frozenset({
    "/.git", "/.env", "/backup", "/config", "/dump", "/sql",
    "/database", "/db", "/private", "/secret", "/credentials",
})

# Admin/login paths → MEDIUM
_ADMIN_PATH_RE = re.compile(
    r"(admin|login|dashboard|manage|panel|wp-admin|cpanel)",
    re.IGNORECASE,
)


def _classify_severity(status: int, path: str) -> Severity:
    """Determine severity based on HTTP status code and path."""
    lower_path = path.lower()

    # Sensitive paths → HIGH
    if lower_path in _SENSITIVE_PATHS or lower_path.startswith("/."):
        return Severity.HIGH

    # Admin/login paths → MEDIUM
    if _ADMIN_PATH_RE.search(path):
        return Severity.MEDIUM

    # Status code classification
    if status >= 500:
        return Severity.HIGH
    if status in (401, 403):
        return Severity.MEDIUM
    if status in (200, 201, 204):
        return Severity.LOW
    if status in (301, 302):
        return Severity.INFORMATIONAL

    return Severity.INFORMATIONAL


def parse_gobuster_output(output: str) -> list[Finding]:
    """Parse Gobuster stdout text into domain findings.

    Args:
        output: The raw stdout captured from a Gobuster directory scan.

    Returns:
        The findings parsed from the output (empty if there were none).
    """
    findings: list[Finding] = []

    for raw_line in output.splitlines():
        line = raw_line.strip()
        if not line:
            continue

        # Skip separator and metadata lines
        if line.startswith("=") or not line.startswith("/"):
            continue

        match = _FINDING_RE.match(line)
        if not match:
            continue

        path = match.group(1)
        status = int(match.group(2))
        size = int(match.group(3))

        severity = _classify_severity(status, path)
        title = f"HTTP {status} — {path}"
        description = f"Status: {status} | Path: {path} | Size: {size}"

        finding = Finding.create(title=title, description=description, severity=severity)
        finding.add_evidence(
            Evidence(
                summary=f"Gobuster: {status} {path}",
                detail=f"status: {status} | path: {path} | size: {size}",
                collected_at=datetime.now(timezone.utc),
            )
        )
        findings.append(finding)

    return findings
