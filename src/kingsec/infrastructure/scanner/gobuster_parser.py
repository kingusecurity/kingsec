"""Parse Gobuster directory enumeration output into domain ``Finding`` objects.

Pure and side-effect-free: given raw stdout text from Gobuster, produce
domain findings. Uses only the standard library (``re``). Malformed or
incomplete lines are logged and skipped rather than failing the whole parse.

Gobuster output format (directory mode):
    Lines containing ``(Status: NNN) [Size: NNN]`` are findings.
    Separator lines (``===``) and metadata lines are skipped.

Base severity mapping (path/status only, before Signal 2 below):
    200/201/204       → LOW  (resource found)
    301/302           → INFORMATIONAL (redirect)
    401/403           → MEDIUM (auth required / forbidden)
    500+              → HIGH (server error)
    Interesting paths → HIGH or MEDIUM based on sensitivity

Phase 2B-c Priority 1b: gobuster's default output has no Content-Type
field, so Signal 1 (content-type mismatch, see ffuf_parser.py) does not
apply here - only Signal 2 (baseline-shape clustering, downgrade-only,
shared with ffuf via severity_demotion.py) does: among this batch's
otherwise-MEDIUM-or-higher results, a (status, size) shape shared by a
large cluster is capped at LOW. A demotion is always recorded on the
Finding (original_severity + demotion_reason), never silent.
"""

from __future__ import annotations

import re
from datetime import UTC, datetime

from kingsec.domain import Evidence, Finding, Severity, SeverityDemotionReason
from kingsec.infrastructure.logging import get_logger

from .severity_demotion import ShapeCandidate, compute_baseline_shape_demotions

_logger = get_logger("kingsec.infrastructure.scanner")

# Pattern: /path                 (Status: 200) [Size: 1234]
_FINDING_RE = re.compile(r"^\s*(\S+)\s+\(Status:\s*(\d+)\)\s+\[Size:\s*(\d+)\]")

# Sensitive paths → HIGH
_SENSITIVE_PATHS = frozenset(
    {
        "/.git",
        "/.env",
        "/backup",
        "/config",
        "/dump",
        "/sql",
        "/database",
        "/db",
        "/private",
        "/secret",
        "/credentials",
    }
)

# Phase 2B-c Priority 1b (approved plan): sensitive paths with no
# recognizable literal/extension match above - same list as ffuf_parser.py,
# named directly from the real Run 2 flood (docs/E2E-EVIDENCE-PHASE2B.md
# Defect 3). Matched as path patterns, not a fixed literal set.
_SENSITIVE_PATH_PATTERNS = (
    re.compile(r"\.git/head", re.IGNORECASE),
    re.compile(r"\.git/config", re.IGNORECASE),
    re.compile(r"(?:^|/)id_rsa(?:$|[/?#])", re.IGNORECASE),
    re.compile(r"\.aws/credentials", re.IGNORECASE),
    re.compile(r"(?:^|/)cosign\.key(?:$|[/?#])", re.IGNORECASE),
    re.compile(r"ws_ftp\.log", re.IGNORECASE),
)

# Admin/login paths → MEDIUM
_ADMIN_PATH_RE = re.compile(
    r"(admin|login|dashboard|manage|panel|wp-admin|cpanel)",
    re.IGNORECASE,
)


def _is_sensitive_path(path: str) -> bool:
    lower_path = path.lower()
    if lower_path in _SENSITIVE_PATHS or lower_path.startswith("/."):
        return True
    return any(pattern.search(path) for pattern in _SENSITIVE_PATH_PATTERNS)


def _base_severity(status: int, path: str) -> Severity:
    """Severity from path/status alone - what a reader relying only on the
    path name and HTTP status would conclude. Signal 2 only ever demotes
    this, never raises it."""
    if _is_sensitive_path(path):
        return Severity.HIGH

    if _ADMIN_PATH_RE.search(path):
        return Severity.MEDIUM

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
    records: list[tuple[str, int, int]] = []  # (path, status, size)

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
        records.append((path, status, size))

    base_severities = [_base_severity(status, path) for path, status, _size in records]

    # Signal 2: baseline-shape clustering, restricted to results that would
    # otherwise score MEDIUM or higher (per-record base classification).
    candidates = [
        ShapeCandidate(index=i, status=status, length=size, base_severity=base_severities[i])
        for i, (_path, status, size) in enumerate(records)
        if base_severities[i] >= Severity.MEDIUM
    ]
    demoted_indices = compute_baseline_shape_demotions(candidates, total_results=len(records))

    findings: list[Finding] = []
    for i, (path, status, size) in enumerate(records):
        base = base_severities[i]
        if i in demoted_indices:
            severity, original_severity, demotion_reason = (
                Severity.LOW,
                base,
                SeverityDemotionReason.BASELINE_SHAPE_MATCH,
            )
        else:
            severity, original_severity, demotion_reason = base, None, None

        title = f"HTTP {status} — {path}"
        description = f"Status: {status} | Path: {path} | Size: {size}"

        finding = Finding.create(
            title=title,
            description=description,
            severity=severity,
            original_severity=original_severity,
            demotion_reason=demotion_reason,
        )
        finding.add_evidence(
            Evidence(
                summary=f"Gobuster: {status} {path}",
                detail=f"status: {status} | path: {path} | size: {size}",
                collected_at=datetime.now(UTC),
            )
        )
        findings.append(finding)

    return findings
