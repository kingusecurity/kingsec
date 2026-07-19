"""Finding Normalization Engine.

Converts ``ScannerResult`` findings from every scanner plugin into one
canonical, immutable ``NormalizedFinding`` representation.

Design principles:
    * Pure domain layer — no infrastructure leakage.
    * Immutable value objects (frozen dataclasses).
    * No plugin-specific logic — extraction rules are generic.
    * Preserves ALL original data: evidence, severity, references, CVEs,
      URLs, affected assets, raw scanner output.
    * Extraction helpers are stateless functions operating on strings.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from datetime import datetime

from kingsec.domain import (
    Evidence,
    Recommendation,
    ScannerResult,
    Severity,
)

# ---------------------------------------------------------------------------
# Normalized value objects
# ---------------------------------------------------------------------------


@dataclass(frozen=True, slots=True)
class NormalizedFinding:
    """An immutable, canonical representation of a security finding.

    Every scanner plugin produces ``Finding`` objects that may differ in
    structure. ``NormalizedFinding`` is the single, unified shape the
    rest of the system consumes. It preserves every piece of original data
    while presenting a consistent interface.
    """

    finding_id: str
    title: str
    description: str
    severity: Severity
    scanner_id: str
    scanner_version: str | None
    evidence: tuple[Evidence, ...]
    recommendations: tuple[Recommendation, ...]
    references: tuple[str, ...]
    affected_assets: tuple[str, ...]
    raw_data: str
    discovered_at: datetime
    tags: tuple[str, ...]
    category: str

    def __post_init__(self) -> None:
        if not self.finding_id:
            raise ValueError("NormalizedFinding.finding_id must not be empty")
        if not self.title:
            raise ValueError("NormalizedFinding.title must not be empty")
        if not isinstance(self.severity, Severity):
            raise TypeError("NormalizedFinding.severity must be a Severity enum")


# ---------------------------------------------------------------------------
# Extraction helpers (stateless, generic)
# ---------------------------------------------------------------------------

# Regex patterns
_CVE_RE = re.compile(r"CVE-\d{4}-\d{4,}", re.IGNORECASE)
_URL_RE = re.compile(r"https?://[^\s<>\"'\)]+")
_IP_RE = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}(?:/\d{1,2})?\b")
_HOSTNAME_RE = re.compile(r"\b(?:[a-zA-Z0-9](?:[a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}\b")
_FILE_PATH_RE = re.compile(r"(?:/[a-zA-Z0-9_.\-]+){2,}")


def extract_references(text: str) -> tuple[str, ...]:
    """Extract URLs and CVE identifiers from text."""
    refs: list[str] = []
    seen: set[str] = set()

    for match in _CVE_RE.finditer(text):
        value = match.group().upper()
        if value not in seen:
            seen.add(value)
            refs.append(value)

    for match in _URL_RE.finditer(text):
        value = match.group().rstrip(".,;:)")
        if value not in seen:
            seen.add(value)
            refs.append(value)

    return tuple(refs)


def extract_affected_assets(text: str) -> tuple[str, ...]:
    """Extract IP addresses, hostnames, and file paths from text."""
    assets: list[str] = []
    seen: set[str] = set()

    for match in _IP_RE.finditer(text):
        value = match.group()
        if value not in seen:
            seen.add(value)
            assets.append(value)

    for match in _HOSTNAME_RE.finditer(text):
        value = match.group()
        if value not in seen:
            seen.add(value)
            assets.append(value)

    for match in _FILE_PATH_RE.finditer(text):
        value = match.group()
        if value not in seen:
            seen.add(value)
            assets.append(value)

    return tuple(assets)


def extract_tags(text: str) -> tuple[str, ...]:
    """Extract lowercase words that look like tags or categories from text."""
    tag_words = {
        "vulnerability", "vuln", "misconfiguration", "misconfig",
        "information", "info", "critical", "high", "medium", "low",
        "injection", "xss", "sqli", "rce", "idor", "ssrf", "csrf",
        "authentication", "authorization", "crypto", "ssl", "tls",
        "hardcoded", "credential", "password", "secret",
        "directory", "traversal", "path-traversal",
        "remote", "local", "code-execution",
        "denial-of-service", "dos",
    }
    lower_text = text.lower()
    found: list[str] = []
    seen: set[str] = set()
    for tag in tag_words:
        if tag in lower_text and tag not in seen:
            seen.add(tag)
            found.append(tag)
    return tuple(found)


def classify_category(severity: Severity, title: str, description: str) -> str:
    """Derive a normalized category string from the finding content."""
    combined = f"{title} {description}".lower()

    if any(w in combined for w in ("injection", "xss", "sqli", "rce", "vulnerability", "vuln", "cve")):
        return "vulnerability"
    if any(w in combined for w in ("crypto", "ssl", "tls", "certificate")):
        return "crypto"
    if any(w in combined for w in ("credential", "password", "auth", "login")):
        return "authentication"
    if any(w in combined for w in ("misconfig", "configuration", "header", "missing")):
        return "misconfiguration"
    if any(w in combined for w in ("directory", "listing", "backup", "exposed")):
        return "exposure"
    if any(w in combined for w in ("subdomain", "dns", "discovery", "enum")):
        return "discovery"
    if any(w in combined for w in ("compliance", "policy", "standard")):
        return "compliance"
    return "information"


# ---------------------------------------------------------------------------
# Normalization engine
# ---------------------------------------------------------------------------


class FindingNormalizer:
    """Converts ``ScannerResult`` objects into ``NormalizedFinding`` objects.

    Stateless: all configuration is provided at construction and stored
    immutably. The ``normalize`` method is a pure function of its input.
    """

    def normalize(self, result: ScannerResult) -> list[NormalizedFinding]:
        """Normalize every finding in a ``ScannerResult``.

        Args:
            result: The scanner result containing domain ``Finding`` objects.

        Returns:
            A list of ``NormalizedFinding`` objects, one per input finding.
        """
        scanner_id = str(result.scanner_id)
        scanner_version = result.scanner_version
        normalized: list[NormalizedFinding] = []

        for finding in result.findings:
            combined_text = f"{finding.title} {finding.description}"
            for ev in finding.evidence:
                combined_text += f" {ev.summary} {ev.detail}"

            references = extract_references(combined_text)
            affected_assets = extract_affected_assets(combined_text)
            tags = extract_tags(combined_text)
            category = classify_category(finding.severity, finding.title, finding.description)

            normalized.append(NormalizedFinding(
                finding_id=str(finding.id),
                title=finding.title,
                description=finding.description,
                severity=finding.severity,
                scanner_id=scanner_id,
                scanner_version=scanner_version,
                evidence=finding.evidence,
                recommendations=finding.recommendations,
                references=references,
                affected_assets=affected_assets,
                raw_data=finding.description,
                discovered_at=finding.discovered_at,
                tags=tags,
                category=category,
            ))

        return normalized

    def normalize_many(self, results: list[ScannerResult]) -> list[NormalizedFinding]:
        """Normalize findings from multiple scanner results.

        Args:
            results: A list of scanner results.

        Returns:
            A flat list of all normalized findings, preserving input order.
        """
        all_normalized: list[NormalizedFinding] = []
        for result in results:
            all_normalized.extend(self.normalize(result))
        return all_normalized
