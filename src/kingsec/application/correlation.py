"""Finding Correlation & Deduplication Engine.

Groups related findings from multiple scanners into one ``CorrelatedFinding``
per unique security issue. Uses only the standard library and is completely
scanner-independent — the correlation key space is CVEs, hostnames, IPs,
URLs, ports, and software names extracted from the finding text.

Design principles:
    * Immutable value objects (frozen dataclasses).
    * Pure functions — no side effects, no mutation.
    * Transitive closure over shared correlation keys.
    * Deterministic and stable output.
    * No infrastructure, plugin, or scanner imports.
"""

from __future__ import annotations

import hashlib
import re
from collections import defaultdict
from dataclasses import dataclass, field
from typing import TYPE_CHECKING

from kingsec.domain import Severity

if TYPE_CHECKING:
    from kingsec.application.normalization import NormalizedFinding


# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

_SOFTWARE_NAMES: frozenset[str] = frozenset({
    "openssh", "ssh", "apache", "httpd", "nginx", "iis",
    "mysql", "mariadb", "postgresql", "postgres", "oracle",
    "redis", "mongodb", "elasticsearch",
    "tomcat", "jetty", "jboss", "wildfly",
    "php", "python", "node", "express",
    "wordpress", "drupal", "joomla",
    "openssl", "ssl", "tls",
    "docker", "kubernetes", "k8s",
    "git", "jenkins", "jira", "confluence",
})

_PORT_PATTERN = re.compile(r"(?:port\s*[:#]?\s*|:)(\d{1,5})", re.IGNORECASE)

_CONFIDENCE_MAP: dict[int, float] = {
    1: 0.35,
    2: 0.60,
    3: 0.80,
}


# ---------------------------------------------------------------------------
# Value object
# ---------------------------------------------------------------------------


@dataclass(frozen=True, slots=True)
class CorrelatedFinding:
    """An immutable, de-duplicated representation of a single security issue.

    Represents the consensus of one or more scanner findings that have been
    correlated into a single issue. All original data is preserved in
    ``merged_findings``.
    """

    correlation_id: str
    title: str
    severity: Severity
    category: str
    affected_assets: tuple[str, ...]
    references: tuple[str, ...]
    scanner_sources: tuple[str, ...]
    merged_findings: tuple["NormalizedFinding", ...]
    confidence: float
    description: str
    recommendations: tuple[str, ...]
    tags: tuple[str, ...]

    def __post_init__(self) -> None:
        if not self.correlation_id:
            raise ValueError("correlation_id must not be empty")
        if not self.title:
            raise ValueError("title must not be empty")
        if not isinstance(self.severity, Severity):
            raise TypeError("severity must be a Severity enum")
        if not self.scanner_sources:
            raise ValueError("scanner_sources must not be empty")
        if not self.merged_findings:
            raise ValueError("merged_findings must not be empty")
        if not 0.0 <= self.confidence <= 1.0:
            raise ValueError("confidence must be between 0.0 and 1.0")


# ---------------------------------------------------------------------------
# Extraction helpers
# ---------------------------------------------------------------------------


def _extract_ports(text: str) -> tuple[str, ...]:
    """Extract port numbers from text."""
    ports: list[str] = []
    seen: set[str] = set()
    for match in _PORT_PATTERN.finditer(text):
        value = match.group(1)
        if value not in seen:
            seen.add(value)
            ports.append(value)
    return tuple(ports)


def _extract_software_names(text: str) -> tuple[str, ...]:
    """Extract known software names from text."""
    lower = text.lower()
    found: list[str] = []
    seen: set[str] = set()
    for sw in _SOFTWARE_NAMES:
        if sw in lower and sw not in seen:
            seen.add(sw)
            found.append(sw)
    return tuple(found)


def _compute_correlation_keys(finding: "NormalizedFinding") -> set[str]:
    """Compute the set of correlation keys for a single finding.

    Two findings are considered related when they share at least one key.
    """
    keys: set[str] = set()
    combined = f"{finding.title} {finding.description}".lower()

    # CVE references (strongest signal)
    for ref in finding.references:
        if ref.upper().startswith("CVE-"):
            keys.add(f"cve:{ref.upper()}")

    # URLs
    for ref in finding.references:
        if ref.startswith("http://") or ref.startswith("https://"):
            keys.add(f"url:{ref}")

    # Affected assets (hostnames, IPs, file paths)
    for asset in finding.affected_assets:
        keys.add(f"asset:{asset}")

    # Software names
    for sw in _extract_software_names(combined):
        keys.add(f"sw:{sw}")

    # Ports (combined with asset for stronger signal)
    for port in _extract_ports(combined):
        keys.add(f"port:{port}")
        for asset in finding.affected_assets:
            keys.add(f"hostport:{asset}:{port}")

    return keys


def _generate_correlation_id(finding_ids: list[str]) -> str:
    """Generate a deterministic correlation ID from merged finding IDs."""
    sorted_ids = sorted(finding_ids)
    combined = "|".join(sorted_ids)
    h = hashlib.sha256(combined.encode()).hexdigest()[:16]
    return f"corr-{h}"


def _compute_confidence(scanner_count: int) -> float:
    """Compute confidence score based on number of unique scanners."""
    return _CONFIDENCE_MAP.get(scanner_count, 1.0)


def _merge_references(reference_lists: list[tuple[str, ...]]) -> tuple[str, ...]:
    """Merge and deduplicate references preserving insertion order."""
    seen: set[str] = set()
    merged: list[str] = []
    for refs in reference_lists:
        for ref in refs:
            if ref not in seen:
                seen.add(ref)
                merged.append(ref)
    return tuple(merged)


def _merge_recommendations(findings: list["NormalizedFinding"]) -> tuple[str, ...]:
    """Merge recommendation text from multiple findings."""
    seen: set[str] = set()
    merged: list[str] = []
    for finding in findings:
        for rec in finding.recommendations:
            line = rec.title + ": " + rec.description
            if line not in seen:
                seen.add(line)
                merged.append(rec.title)
    return tuple(merged)


def _find_connected_groups(
    findings: list["NormalizedFinding"],
) -> list[list["NormalizedFinding"]]:
    """Group findings into connected components via shared correlation keys.

    Uses union-find for O(n α(n)) performance.
    """
    if not findings:
        return []

    key_to_indices: dict[str, list[int]] = defaultdict(list)
    for i, finding in enumerate(findings):
        for key in _compute_correlation_keys(finding):
            key_to_indices[key].append(i)

    # Union-Find (path compression only)
    parent = list(range(len(findings)))

    def find(x: int) -> int:
        while parent[x] != x:
            parent[x] = parent[parent[x]]
            x = parent[x]
        return x

    def union(x: int, y: int) -> None:
        rx, ry = find(x), find(y)
        if rx != ry:
            parent[ry] = rx

    for indices in key_to_indices.values():
        if len(indices) > 1:
            root = indices[0]
            for idx in indices[1:]:
                union(root, idx)

    groups: dict[int, list["NormalizedFinding"]] = defaultdict(list)
    for i, finding in enumerate(findings):
        groups[find(i)].append(finding)

    return list(groups.values())


# ---------------------------------------------------------------------------
# Correlation Engine
# ---------------------------------------------------------------------------


class CorrelationEngine:
    """Groups related scanner findings into correlated, deduplicated issues.

    Stateless and pure — all methods are deterministic functions of their
    input. Use ``correlate()`` for the main pipeline, ``group_by_*`` for
    alternative views.
    """

    # ------------------------------------------------------------------
    # Main correlation pipeline
    # ------------------------------------------------------------------

    def correlate(
        self, findings: list["NormalizedFinding"]
    ) -> list[CorrelatedFinding]:
        """Correlate a list of normalized findings into deduplicated issues.

        Args:
            findings: Normalized findings from one or more scanners.

        Returns:
            A list of ``CorrelatedFinding`` objects, one per unique issue.
        """
        if not findings:
            return []

        groups = _find_connected_groups(findings)

        correlated: list[CorrelatedFinding] = []
        for group in groups:
            correlated.append(self._build_correlated(group))

        # Sort by severity descending, then by title for stable order.
        correlated.sort(key=lambda c: (c.severity, c.title), reverse=True)
        return correlated

    # ------------------------------------------------------------------
    # Grouping views (for analysis, not deduplication)
    # ------------------------------------------------------------------

    def group_by_asset(
        self, findings: list["NormalizedFinding"]
    ) -> dict[str, list["NormalizedFinding"]]:
        """Group findings by affected asset (hostname, IP, file path).

        Returns:
            A dict keyed by asset string. A finding may appear under
            multiple assets if it affects more than one.
        """
        result: dict[str, list["NormalizedFinding"]] = defaultdict(list)
        for finding in findings:
            for asset in (finding.affected_assets or ("unknown",)):
                result[asset].append(finding)
        return dict(result)

    def group_by_category(
        self, findings: list["NormalizedFinding"]
    ) -> dict[str, list["NormalizedFinding"]]:
        """Group findings by their normalized category.

        Returns:
            A dict keyed by category string. Every finding has a
            category, so every finding appears exactly once.
        """
        result: dict[str, list["NormalizedFinding"]] = defaultdict(list)
        for finding in findings:
            result[finding.category].append(finding)
        return dict(result)

    def group_by_severity(
        self, findings: list["NormalizedFinding"]
    ) -> dict[Severity, list["NormalizedFinding"]]:
        """Group findings by severity level.

        Returns:
            A dict keyed by ``Severity``, ordered from highest to lowest.
        """
        result: dict[Severity, list["NormalizedFinding"]] = defaultdict(list)
        for finding in findings:
            result[finding.severity].append(finding)
        return dict(result)

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    @staticmethod
    def _build_correlated(
        group: list["NormalizedFinding"],
    ) -> CorrelatedFinding:
        """Build one ``CorrelatedFinding`` from a group of related findings."""
        # Collect all scanner sources (unique, preserving order)
        scanner_sources: list[str] = []
        seen_scanners: set[str] = set()
        for f in group:
            if f.scanner_id not in seen_scanners:
                seen_scanners.add(f.scanner_id)
                scanner_sources.append(f.scanner_id)

        # Highest severity wins
        max_severity = max(f.severity for f in group)

        # Merge references
        merged_refs = _merge_references([f.references for f in group])

        # Extract category (use the one from findings with highest severity)
        sorted_by_sev = sorted(group, key=lambda f: f.severity, reverse=True)
        category = sorted_by_sev[0].category

        # Generate a descriptive title
        title = _derive_title(group, max_severity)

        # Build description summary
        description = _derive_description(group)

        # Merge affected assets
        all_assets: list[str] = []
        seen_assets: set[str] = set()
        for f in sorted_by_sev:
            for asset in f.affected_assets:
                if asset not in seen_assets:
                    seen_assets.add(asset)
                    all_assets.append(asset)
        if not all_assets:
            all_assets = ["unknown"]

        # Merge tags
        all_tags: list[str] = []
        seen_tags: set[str] = set()
        for f in sorted_by_sev:
            for tag in f.tags:
                if tag not in seen_tags:
                    seen_tags.add(tag)
                    all_tags.append(tag)

        # Merge recommendations
        merged_recs = _merge_recommendations(sorted_by_sev)

        # Confidence based on unique scanner count
        confidence = _compute_confidence(len(scanner_sources))

        # Correlation ID from merged finding IDs
        finding_ids = [str(f.finding_id) for f in group]
        corr_id = _generate_correlation_id(finding_ids)

        return CorrelatedFinding(
            correlation_id=corr_id,
            title=title,
            severity=max_severity,
            category=category,
            affected_assets=tuple(all_assets),
            references=merged_refs,
            scanner_sources=tuple(scanner_sources),
            merged_findings=tuple(sorted_by_sev),
            confidence=confidence,
            description=description,
            recommendations=merged_recs,
            tags=tuple(all_tags),
        )


# ---------------------------------------------------------------------------
# Stateless title / description derivation
# ---------------------------------------------------------------------------


def _derive_title(
    group: list["NormalizedFinding"], max_severity: Severity
) -> str:
    """Derive a single descriptive title for a correlated finding."""
    # Use the first CVE reference as the title anchor if available
    for f in group:
        for ref in f.references:
            if ref.upper().startswith("CVE-"):
                return f"{ref} — {f.title}"

    # Fall back to the title of the highest-severity finding
    sorted_by_sev = sorted(group, key=lambda f: f.severity, reverse=True)
    return sorted_by_sev[0].title


def _derive_description(
    group: list["NormalizedFinding"],
) -> str:
    """Derive a consolidated description from grouped findings."""
    sorted_by_sev = sorted(group, key=lambda f: f.severity, reverse=True)

    parts: list[str] = []
    parts.append(f"Correlated from {len(sorted_by_sev)} finding(s) "
                 f"across {len({f.scanner_id for f in sorted_by_sev})} scanner(s).")

    for f in sorted_by_sev:
        parts.append(f"[{f.scanner_id}] {f.title} — {f.description[:120]}")

    return "\n".join(parts)
