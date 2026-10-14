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
    # Short acronyms use word boundaries: without them, "RCE" matches the
    # "rce" inside ordinary words like "force" (proven live: Nikto's
    # "No CGI Directories found (use '-C all' to force check...)" line
    # was scored CRITICAL because of the "rce" in "force").
    re.compile(r"\bRCE\b|remote code execution", re.IGNORECASE),
    re.compile(r"command injection", re.IGNORECASE),
    re.compile(r"backdoor", re.IGNORECASE),
    re.compile(r"remote file inclusion|\bRFI\b", re.IGNORECASE),
    re.compile(r"SQL injection|\bSQLi\b", re.IGNORECASE),
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
    "+ Proxy",
)

# Nikto self-status / summary lines that start with "+" but describe the
# scanner's own run, not the target. Emitting them as findings pollutes
# reports (e.g. "CGI tests skipped" is not a vulnerability).
#
# The summary-line pattern deliberately matches the COUNTS, not the
# prefix: Nikto 2.5+ prints "Scan terminated: 19 errors and 26 items
# reported on the remote host" while older releases print "8026
# requests: 0 errors and 13 items reported". A prefix-anchored pattern
# ("\\d+ requests: ...") silently missed the modern format and the
# summary line shipped as a report finding (proven live, 2026-10-14).
#
# _ARRAY_REF_RE is the same class of defect one level down: Nikto
# occasionally emits an un-stringified Perl reference for the OPTIONS
# methods list ("Allowed HTTP Methods: ARRAY(0x5638...)") - a
# scanner-side rendering bug carrying zero information about the
# target. It is skipped (with a debug log) rather than ingested.
_ARRAY_REF_RE = re.compile(r"ARRAY\(0x[0-9a-fA-F]+\)", re.IGNORECASE)

_SKIP_PATTERNS: tuple[re.Pattern[str], ...] = (
    re.compile(r"No CGI Directories found", re.IGNORECASE),
    re.compile(r"CGI tests skipped", re.IGNORECASE),
    re.compile(r"\d+ errors? and \d+ items? reported", re.IGNORECASE),
    re.compile(r"\d+ host\(s\) tested", re.IGNORECASE),
    _ARRAY_REF_RE,
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
        if any(pat.search(line) for pat in _SKIP_PATTERNS):
            if _ARRAY_REF_RE.search(line):
                # The line's only "content" is a memory address - make the
                # drop visible in logs so a real methods-enumeration result
                # going missing would be noticed, not silently assumed.
                _logger.debug("skipping nikto line with un-stringified ARRAY reference: %s", line[:80])
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
