"""Parse Nikto text output into domain ``Finding`` objects.

Pure and side-effect-free: given raw stdout text from Nikto, produce
domain findings. Uses only the standard library. Malformed or incomplete
data is logged and skipped rather than failing the whole parse.

Nikto output format:
    Lines beginning with ``+`` are findings. Metadata lines (Target IP,
    Start Time, etc.) are skipped. Lines beginning with ``-`` are
    separators and are ignored.

Severity mapping (conservative):
    Server banner, info        → INFORMATIONAL
    Missing security headers   → LOW
    Directory indexing          → MEDIUM
    OSVDB entries / known vuln → HIGH
    RCE indicators             → CRITICAL
"""

from __future__ import annotations

import re
from datetime import UTC, datetime

from kingsec.domain import Evidence, Finding, Severity
from kingsec.infrastructure.logging import get_logger

_logger = get_logger("kingsec.infrastructure.scanner")

# Patterns that classify a finding line into a severity bucket.
# Order matters: first match wins in _classify_line.
_PATTERNS_HIGH: tuple[re.Pattern[str], ...] = (
    re.compile(r"OSVDB-\d+", re.IGNORECASE),
    re.compile(r"outdated", re.IGNORECASE),
    re.compile(r"vulnerable", re.IGNORECASE),
)

_PATTERNS_CRITICAL: tuple[re.Pattern[str], ...] = (
    re.compile(r"RCE|remote code execution", re.IGNORECASE),
    re.compile(r"command injection", re.IGNORECASE),
    re.compile(r"backdoor", re.IGNORECASE),
    re.compile(r"remote file inclusion|RFI", re.IGNORECASE),
    re.compile(r"SQL injection|SQLi", re.IGNORECASE),
)

_PATTERNS_MEDIUM: tuple[re.Pattern[str], ...] = (
    re.compile(r"directory indexing", re.IGNORECASE),
    re.compile(r"directory found", re.IGNORECASE),
    re.compile(r"admin", re.IGNORECASE),
    re.compile(r"config file", re.IGNORECASE),
    re.compile(r"backup file", re.IGNORECASE),
    re.compile(r"log file", re.IGNORECASE),
    re.compile(r"sensitive", re.IGNORECASE),
)

_PATTERNS_LOW: tuple[re.Pattern[str], ...] = (
    re.compile(r"header is not present", re.IGNORECASE),
    re.compile(r"header is not set", re.IGNORECASE),
    re.compile(r"X-Content-Type-Options", re.IGNORECASE),
    re.compile(r"X-Frame-Options", re.IGNORECASE),
    re.compile(r"CSP|Content-Security-Policy", re.IGNORECASE),
    re.compile(r"cookie without.*httponly", re.IGNORECASE),
    re.compile(r"cookie without.*secure", re.IGNORECASE),
)

# Lines to skip entirely (metadata, separators, summary).
_SKIP_PREFIXES = (
    "-",
    "+ Target IP:",
    "+ Target Hostname:",
    "+ Target Port:",
    "+ Start Time:",
    "+ End Time:",
    "+ Host(s) tested",
    "+ Proxy",
)


def _classify_line(line: str) -> Severity:
    """Determine severity for a Nikto finding line."""
    for pat in _PATTERNS_CRITICAL:
        if pat.search(line):
            return Severity.CRITICAL
    for pat in _PATTERNS_HIGH:
        if pat.search(line):
            return Severity.HIGH
    for pat in _PATTERNS_MEDIUM:
        if pat.search(line):
            return Severity.MEDIUM
    for pat in _PATTERNS_LOW:
        if pat.search(line):
            return Severity.LOW
    return Severity.INFORMATIONAL


def parse_nikto_output(output: str) -> list[Finding]:
    """Parse Nikto stdout text into domain findings.

    Args:
        output: The raw stdout captured from a Nikto run.

    Returns:
        The findings parsed from the output (empty if there were none).
    """
    findings: list[Finding] = []

    for raw_line in output.splitlines():
        line = raw_line.strip()
        if not line:
            continue

        # Skip non-finding lines
        if any(line.startswith(prefix) for prefix in _SKIP_PREFIXES):
            continue

        # Only process finding lines (start with +)
        if not line.startswith("+"):
            continue

        # Strip the leading "+ " prefix
        finding_text = line[2:].strip() if len(line) > 2 else ""
        if not finding_text:
            continue

        severity = _classify_line(finding_text)
        finding = Finding.create(
            title=finding_text,
            description=finding_text,
            severity=severity,
        )
        finding.add_evidence(
            Evidence(
                summary=f"Nikto finding: {finding_text[:80]}",
                detail=f"raw: {line}",
                collected_at=datetime.now(UTC),
            )
        )
        findings.append(finding)

    return findings
