"""Finding Correlation Engine: comprehensive tests."""

from __future__ import annotations

from datetime import UTC, datetime

import pytest

from kingsec.application.correlation import (
    CorrelatedFinding,
    CorrelationEngine,
    _compute_confidence,
    _derive_description,
    _derive_title,
    _generate_correlation_id,
    _merge_references,
)
from kingsec.application.normalization import NormalizedFinding
from kingsec.domain import Evidence, Recommendation, Severity

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

_NOW = datetime.now(UTC)


def _make_nf(
    title: str = "OpenSSH CVE-2023-38408",
    description: str = "OpenSSH vulnerability on host 10.0.0.5 port 22",
    severity: Severity = Severity.HIGH,
    scanner_id: str = "nuclei",
    references: tuple[str, ...] = ("CVE-2023-38408",),
    affected_assets: tuple[str, ...] = ("10.0.0.5",),
    category: str = "vulnerability",
    tags: tuple[str, ...] = ("ssh", "openssh", "vulnerability"),
    scanner_version: str | None = "3.0.0",
    recommendations: tuple[Recommendation, ...] = (),
) -> NormalizedFinding:
    return NormalizedFinding(
        finding_id=f"find-{title.lower().replace(' ', '-')[:16]}",
        title=title,
        description=description,
        severity=severity,
        scanner_id=scanner_id,
        scanner_version=scanner_version,
        evidence=(
            Evidence(summary="Evidence", detail="Detail", collected_at=_NOW),
        ),
        recommendations=recommendations,
        references=references,
        affected_assets=affected_assets,
        raw_data=description,
        discovered_at=_NOW,
        tags=tags,
        category=category,
    )


_SSH_NUCLEI = _make_nf(
    title="OpenSSH CVE-2023-38408",
    description="OpenSSH vulnerability on 10.0.0.5:22",
    severity=Severity.HIGH,
    scanner_id="nuclei",
    references=("CVE-2023-38408",),
    affected_assets=("10.0.0.5",),
    tags=("ssh", "openssh", "vuln"),
)

_SSH_NMAP = _make_nf(
    title="SSH Server Outdated",
    description="SSH server on 10.0.0.5:22 running OpenSSH 8.2",
    severity=Severity.MEDIUM,
    scanner_id="nmap",
    references=(),
    affected_assets=("10.0.0.5",),
    tags=("ssh", "openssh"),
)

_SSH_NIKTO = _make_nf(
    title="OpenSSH Vulnerability",
    description="OpenSSH 8.2 detected on 10.0.0.5",
    severity=Severity.LOW,
    scanner_id="nikto",
    references=(),
    affected_assets=("10.0.0.5",),
    tags=("ssh",),
)

_WEB_NUCLEI = _make_nf(
    title="Apache RCE CVE-2024-1234",
    description="Apache HTTPD RCE on web.example.com:80",
    severity=Severity.CRITICAL,
    scanner_id="nuclei",
    references=("CVE-2024-1234", "https://example.com/advisory"),
    affected_assets=("web.example.com", "192.168.1.10"),
    category="vulnerability",
    tags=("rce", "apache", "vuln"),
)

_WEB_ZAP = _make_nf(
    title="Apache Vulnerability",
    description="Apache server on web.example.com outdated",
    severity=Severity.HIGH,
    scanner_id="zap",
    references=(),
    affected_assets=("web.example.com",),
    category="vulnerability",
    tags=("apache",),
)

_SQL_NUCLEI = _make_nf(
    title="SQL Injection",
    description="SQL injection in login form on 10.0.0.5",
    severity=Severity.CRITICAL,
    scanner_id="nuclei",
    references=("CVE-2022-1111",),
    affected_assets=("10.0.0.5",),
    tags=("sqli", "injection"),
)

_ENGINE = CorrelationEngine()


# ===========================================================================
# CorrelatedFinding construction
# ===========================================================================


class TestCorrelatedFindingConstruction:
    def test_creates_with_valid_data(self) -> None:
        cf = CorrelatedFinding(
            correlation_id="corr-abc123",
            title="Test Issue",
            severity=Severity.HIGH,
            category="vulnerability",
            affected_assets=("10.0.0.1",),
            references=("CVE-2024-0001",),
            scanner_sources=("nuclei",),
            merged_findings=(_SSH_NUCLEI,),
            confidence=0.35,
            description="A test issue",
            recommendations=(),
            tags=("test",),
        )
        assert cf.correlation_id == "corr-abc123"

    def test_frozen_immutable(self) -> None:
        cf = CorrelatedFinding(
            correlation_id="corr-abc",
            title="Test",
            severity=Severity.LOW,
            category="info",
            affected_assets=("asset",),
            references=(),
            scanner_sources=("nmap",),
            merged_findings=(_SSH_NUCLEI,),
            confidence=0.35,
            description="Desc",
            recommendations=(),
            tags=(),
        )
        with pytest.raises(AttributeError):
            cf.title = "Changed"  # type: ignore[misc]

    def test_empty_correlation_id_raises(self) -> None:
        with pytest.raises(ValueError, match="correlation_id"):
            CorrelatedFinding(
                correlation_id="",
                title="Test",
                severity=Severity.LOW,
                category="info",
                affected_assets=(),
                references=(),
                scanner_sources=("nmap",),
                merged_findings=(_SSH_NUCLEI,),
                confidence=0.35,
                description="",
                recommendations=(),
                tags=(),
            )

    def test_empty_title_raises(self) -> None:
        with pytest.raises(ValueError, match="title"):
            CorrelatedFinding(
                correlation_id="corr-abc",
                title="",
                severity=Severity.LOW,
                category="info",
                affected_assets=(),
                references=(),
                scanner_sources=("nmap",),
                merged_findings=(_SSH_NUCLEI,),
                confidence=0.35,
                description="",
                recommendations=(),
                tags=(),
            )

    def test_empty_scanner_sources_raises(self) -> None:
        with pytest.raises(ValueError, match="scanner_sources"):
            CorrelatedFinding(
                correlation_id="corr-abc",
                title="Test",
                severity=Severity.LOW,
                category="info",
                affected_assets=(),
                references=(),
                scanner_sources=(),
                merged_findings=(_SSH_NUCLEI,),
                confidence=0.35,
                description="",
                recommendations=(),
                tags=(),
            )

    def test_empty_merged_findings_raises(self) -> None:
        with pytest.raises(ValueError, match="merged_findings"):
            CorrelatedFinding(
                correlation_id="corr-abc",
                title="Test",
                severity=Severity.LOW,
                category="info",
                affected_assets=(),
                references=(),
                scanner_sources=("nmap",),
                merged_findings=(),
                confidence=0.35,
                description="",
                recommendations=(),
                tags=(),
            )

    def test_confidence_out_of_range_raises(self) -> None:
        with pytest.raises(ValueError, match="confidence"):
            CorrelatedFinding(
                correlation_id="corr-abc",
                title="Test",
                severity=Severity.LOW,
                category="info",
                affected_assets=(),
                references=(),
                scanner_sources=("nmap",),
                merged_findings=(_SSH_NUCLEI,),
                confidence=1.5,
                description="",
                recommendations=(),
                tags=(),
            )

    def test_non_severity_raises(self) -> None:
        with pytest.raises(TypeError):
            CorrelatedFinding(
                correlation_id="corr-abc",
                title="Test",
                severity="HIGH",  # type: ignore[arg-type]
                category="info",
                affected_assets=(),
                references=(),
                scanner_sources=("nmap",),
                merged_findings=(_SSH_NUCLEI,),
                confidence=0.35,
                description="",
                recommendations=(),
                tags=(),
            )


# ===========================================================================
# Correlation — single finding
# ===========================================================================


class TestCorrelateSingle:
    def test_single_finding_returns_one(self) -> None:
        result = _ENGINE.correlate([_SSH_NUCLEI])
        assert len(result) == 1

    def test_single_finding_preserves_title(self) -> None:
        result = _ENGINE.correlate([_SSH_NUCLEI])
        assert "OpenSSH" in result[0].title

    def test_single_finding_preserves_severity(self) -> None:
        result = _ENGINE.correlate([_SSH_NUCLEI])
        assert result[0].severity is Severity.HIGH

    def test_single_finding_preserves_assets(self) -> None:
        result = _ENGINE.correlate([_SSH_NUCLEI])
        assert "10.0.0.5" in result[0].affected_assets

    def test_single_finding_scanner_sources(self) -> None:
        result = _ENGINE.correlate([_SSH_NUCLEI])
        assert result[0].scanner_sources == ("nuclei",)

    def test_single_finding_confidence(self) -> None:
        result = _ENGINE.correlate([_SSH_NUCLEI])
        assert result[0].confidence == 0.35

    def test_single_finding_merged_findings(self) -> None:
        result = _ENGINE.correlate([_SSH_NUCLEI])
        assert len(result[0].merged_findings) == 1

    def test_single_finding_stable_id(self) -> None:
        r1 = _ENGINE.correlate([_SSH_NUCLEI])
        r2 = _ENGINE.correlate([_SSH_NUCLEI])
        assert r1[0].correlation_id == r2[0].correlation_id


# ===========================================================================
# Correlation — multiple findings
# ===========================================================================


class TestCorrelateMultiple:
    def test_same_cve_merged(self) -> None:
        a = _make_nf(title="A CVE-2024-0001", references=("CVE-2024-0001",))
        b = _make_nf(title="B CVE-2024-0001", references=("CVE-2024-0001",))
        result = _ENGINE.correlate([a, b])
        assert len(result) == 1

    def test_different_cve_separate(self) -> None:
        a = _make_nf(title="A CVE-2024-0001", references=("CVE-2024-0001",),
                     affected_assets=("10.0.0.1",),
                     description="Issue A on host 10.0.0.1", tags=())
        b = _make_nf(title="B CVE-2025-0002", references=("CVE-2025-0002",),
                     affected_assets=("10.0.0.2",),
                     description="Issue B on host 10.0.0.2", tags=())
        result = _ENGINE.correlate([a, b])
        assert len(result) == 2

    def test_same_asset_same_software_merged(self) -> None:
        result = _ENGINE.correlate([_SSH_NMAP, _SSH_NIKTO])
        assert len(result) == 1

    def test_different_assets_separate(self) -> None:
        a = _make_nf(title="A", affected_assets=("10.0.0.1",), references=(),
                     tags=(), description="Issue on host 10.0.0.1")
        b = _make_nf(title="B", affected_assets=("10.0.0.2",), references=(),
                     tags=(), description="Issue on host 10.0.0.2")
        result = _ENGINE.correlate([a, b])
        assert len(result) == 2

    def test_unrelated_findings_separate(self) -> None:
        result = _ENGINE.correlate([_SSH_NUCLEI, _WEB_NUCLEI])
        assert len(result) == 2

    def test_ssh_correlation_merges_three(self) -> None:
        result = _ENGINE.correlate([_SSH_NUCLEI, _SSH_NMAP, _SSH_NIKTO])
        assert len(result) == 1

    def test_hybrid_ssh_and_web_properly_split(self) -> None:
        result = _ENGINE.correlate([_SSH_NUCLEI, _SSH_NMAP, _WEB_NUCLEI, _WEB_ZAP])
        assert len(result) == 2

    def test_empty_input(self) -> None:
        result = _ENGINE.correlate([])
        assert result == []

    def test_deterministic_order(self) -> None:
        findings = [_SSH_NUCLEI, _SSH_NMAP, _WEB_NUCLEI]
        r1 = _ENGINE.correlate(findings)
        r2 = _ENGINE.correlate(findings)
        for i in range(len(r1)):
            assert r1[i].correlation_id == r2[i].correlation_id

    def test_correlation_id_stable_across_runs(self) -> None:
        findings = [_SSH_NUCLEI, _SSH_NMAP, _SSH_NIKTO]
        result = _ENGINE.correlate(findings)
        assert len(result) == 1
        assert result[0].correlation_id.startswith("corr-")

    def test_transitive_correlation(self) -> None:
        a = _make_nf(title="A", references=("CVE-2024-0001",), affected_assets=("10.0.0.1",))
        b = _make_nf(title="B", references=("CVE-2024-0001",), affected_assets=("10.0.0.2",))
        c = _make_nf(title="C", references=(),
                      affected_assets=("10.0.0.2",), tags=("ssh",))
        # A and B share CVE → merge
        # B and C share asset 10.0.0.2 → merge
        # Therefore A, B, C all merge transitively
        result = _ENGINE.correlate([a, b, c])
        assert len(result) == 1


class TestSeverityMerge:
    def test_highest_severity_wins(self) -> None:
        a = _make_nf(severity=Severity.LOW, references=("CVE-2024-0001",))
        b = _make_nf(severity=Severity.HIGH, references=("CVE-2024-0001",))
        result = _ENGINE.correlate([a, b])
        assert result[0].severity is Severity.HIGH

    def test_all_severities(self) -> None:
        findings = [
            _make_nf(severity=Severity.INFORMATIONAL, references=("CVE-2024-0001",)),
            _make_nf(severity=Severity.LOW, references=("CVE-2024-0001",)),
            _make_nf(severity=Severity.MEDIUM, references=("CVE-2024-0001",)),
            _make_nf(severity=Severity.HIGH, references=("CVE-2024-0001",)),
            _make_nf(severity=Severity.CRITICAL, references=("CVE-2024-0001",)),
        ]
        result = _ENGINE.correlate(findings)
        assert result[0].severity is Severity.CRITICAL

    def test_critical_wins_over_high(self) -> None:
        result = _ENGINE.correlate([_SSH_NMAP, _WEB_NUCLEI])
        web_corr = [c for c in result if "Apache" in c.title or "CVE-2024" in c.title]
        assert len(web_corr) >= 1
        assert web_corr[0].severity is Severity.CRITICAL


class TestReferenceMerge:
    def test_merges_and_deduplicates(self) -> None:
        a = _make_nf(references=("CVE-2024-0001", "https://a.com"))
        b = _make_nf(references=("CVE-2024-0001", "https://b.com"))
        result = _ENGINE.correlate([a, b])
        refs = result[0].references
        assert "CVE-2024-0001" in refs
        assert "https://a.com" in refs
        assert "https://b.com" in refs
        assert refs.count("CVE-2024-0001") == 1

    def test_preserves_order(self) -> None:
        a = _make_nf(references=("CVE-2024-0001",))
        b = _make_nf(references=("CVE-2024-0002", "CVE-2024-0003"))
        result = _ENGINE.correlate([a, b])
        refs = result[0].references
        assert refs.index("CVE-2024-0001") < refs.index("CVE-2024-0002")


class TestScannerSources:
    def test_collects_unique_sources(self) -> None:
        result = _ENGINE.correlate([_SSH_NUCLEI, _SSH_NMAP, _SSH_NIKTO])
        assert "nuclei" in result[0].scanner_sources
        assert "nmap" in result[0].scanner_sources
        assert "nikto" in result[0].scanner_sources

    def test_deduplicates_same_scanner(self) -> None:
        a = _make_nf(scanner_id="nuclei", references=("CVE-2024-0001",))
        b = _make_nf(scanner_id="nuclei", references=("CVE-2024-0001",))
        result = _ENGINE.correlate([a, b])
        assert len(result[0].scanner_sources) == 1


class TestConfidence:
    def test_one_scanner(self) -> None:
        assert _compute_confidence(1) == 0.35

    def test_two_scanners(self) -> None:
        assert _compute_confidence(2) == 0.60

    def test_three_scanners(self) -> None:
        assert _compute_confidence(3) == 0.80

    def test_four_plus_scanners(self) -> None:
        assert _compute_confidence(4) == 1.0
        assert _compute_confidence(5) == 1.0

    def test_correlated_confidence_one(self) -> None:
        result = _ENGINE.correlate([_SSH_NUCLEI])
        assert result[0].confidence == 0.35

    def test_correlated_confidence_two(self) -> None:
        result = _ENGINE.correlate([_SSH_NUCLEI, _SSH_NMAP])
        assert result[0].confidence == 0.60

    def test_correlated_confidence_three(self) -> None:
        result = _ENGINE.correlate([_SSH_NUCLEI, _SSH_NMAP, _SSH_NIKTO])
        assert result[0].confidence == 0.80


# ===========================================================================
# Category preservation
# ===========================================================================


class TestCategory:
    def test_preserves_category_from_highest_severity(self) -> None:
        a = _make_nf(severity=Severity.CRITICAL, references=("CVE-2024-0001",))
        result = _ENGINE.correlate([_SSH_NMAP, a])
        ssh_corr = [c for c in result if "CVE-2024" in c.title]
        assert len(ssh_corr) == 1
        assert ssh_corr[0].category == "vulnerability"

    def test_category_from_first_highest(self) -> None:
        findings = [
            _make_nf(severity=Severity.MEDIUM, references=("CVE-2024-0001",),
                     category="misconfiguration"),
            _make_nf(severity=Severity.CRITICAL, references=("CVE-2024-0001",)),
        ]
        result = _ENGINE.correlate(findings)
        assert result[0].category == "vulnerability"


# ===========================================================================
# Grouping
# ===========================================================================


class TestGroupByAsset:
    def test_groups_by_asset(self) -> None:
        groups = _ENGINE.group_by_asset([_SSH_NUCLEI, _WEB_NUCLEI])
        assert "10.0.0.5" in groups
        assert "web.example.com" in groups
        assert "192.168.1.10" in groups

    def test_asset_with_multiple_findings(self) -> None:
        groups = _ENGINE.group_by_asset([_SSH_NUCLEI, _SSH_NMAP])
        assert len(groups.get("10.0.0.5", [])) == 2

    def test_empty_input(self) -> None:
        assert _ENGINE.group_by_asset([]) == {}


class TestGroupByCategory:
    def test_groups_by_category(self) -> None:
        a = _make_nf(category="vulnerability")
        b = _make_nf(category="misconfiguration", references=("CVE-2024-0001",))
        groups = _ENGINE.group_by_category([a, b])
        assert "vulnerability" in groups
        assert "misconfiguration" in groups

    def test_empty_input(self) -> None:
        assert _ENGINE.group_by_category([]) == {}


class TestGroupBySeverity:
    def test_groups_by_severity(self) -> None:
        a = _make_nf(severity=Severity.HIGH, references=("CVE-2024-0001",))
        b = _make_nf(severity=Severity.LOW, references=("CVE-2024-0002",))
        groups = _ENGINE.group_by_severity([a, b])
        assert Severity.HIGH in groups
        assert Severity.LOW in groups

    def test_multiple_in_same_severity(self) -> None:
        a = _make_nf(severity=Severity.HIGH, references=("CVE-2024-0001",))
        b = _make_nf(severity=Severity.HIGH, references=("CVE-2024-0002",))
        groups = _ENGINE.group_by_severity([a, b])
        assert len(groups[Severity.HIGH]) == 2

    def test_empty_input(self) -> None:
        assert _ENGINE.group_by_severity([]) == {}


# ===========================================================================
# Merge helpers
# ===========================================================================


class TestMergeReferences:
    def test_merges_no_duplicates(self) -> None:
        result = _merge_references([("a", "b"), ("b", "c")])
        assert result == ("a", "b", "c")

    def test_empty_input(self) -> None:
        assert _merge_references([]) == ()

    def preserves_order(self) -> None:
        result = _merge_references([("z", "a"), ("m",)])
        assert result[0] == "z"


class TestGenerateCorrelationId:
    def test_deterministic(self) -> None:
        ids = ["a", "b"]
        r1 = _generate_correlation_id(ids)
        r2 = _generate_correlation_id(ids)
        assert r1 == r2

    def test_different_ids_different_ids(self) -> None:
        assert _generate_correlation_id(["a"]) != _generate_correlation_id(["b"])

    def test_starts_with_corr(self) -> None:
        assert _generate_correlation_id(["a"]).startswith("corr-")

    def test_sorts_ids(self) -> None:
        r1 = _generate_correlation_id(["b", "a"])
        r2 = _generate_correlation_id(["a", "b"])
        assert r1 == r2


class TestDeriveTitle:
    def test_uses_cve_if_available(self) -> None:
        f = _make_nf(references=("CVE-2024-0001",))
        title = _derive_title([f], Severity.HIGH)
        assert "CVE-2024-0001" in title

    def test_falls_back_to_first_severity_title(self) -> None:
        f = _make_nf(references=())
        title = _derive_title([f], Severity.LOW)
        assert title == f.title


class TestDeriveDescription:
    def test_contains_correlated_count(self) -> None:
        desc = _derive_description([_SSH_NUCLEI, _SSH_NMAP])
        assert "2 finding(s)" in desc

    def test_contains_scanner_count(self) -> None:
        desc = _derive_description([_SSH_NUCLEI, _SSH_NMAP])
        assert "2 scanner(s)" in desc

    def test_contains_finding_details(self) -> None:
        desc = _derive_description([_SSH_NUCLEI])
        assert "[nuclei]" in desc


# ===========================================================================
# Edge cases
# ===========================================================================


class TestEdgeCases:
    def test_no_shared_keys_remains_separate(self) -> None:
        findings = [
            _make_nf(title="Issue A", references=("CVE-2024-0001",),
                     affected_assets=("10.0.0.1",),
                     tags=(), description="Issue A on 10.0.0.1"),
            _make_nf(title="Issue B", references=("CVE-2025-0002",),
                     affected_assets=("10.0.0.2",),
                     tags=(), description="Issue B on 10.0.0.2"),
        ]
        result = _ENGINE.correlate(findings)
        assert len(result) == 2

    def test_large_dataset(self) -> None:
        n = 50
        findings = [
            _make_nf(
                title=f"Finding {i}",
                description=f"A unique issue number {i}",
                references=(f"CVE-2024-{i:04d}",),
                affected_assets=(f"10.0.0.{i}",),
                tags=(),
            )
            for i in range(n)
        ]
        result = _ENGINE.correlate(findings)
        # Every finding has a unique CVE and a unique asset, so none share
        # any correlation key.
        assert len(result) == 50

    def test_no_references_uses_asset(self) -> None:
        a = _make_nf(
            title="OpenSSH issue", references=(),
            affected_assets=("10.0.0.5",), tags=("ssh", "openssh"),
        )
        b = _make_nf(
            title="SSH problem", references=(),
            affected_assets=("10.0.0.5",), tags=("ssh",),
        )
        result = _ENGINE.correlate([a, b])
        assert len(result) == 1

    def test_result_is_immutable(self) -> None:
        result = _ENGINE.correlate([_SSH_NUCLEI])
        with pytest.raises(AttributeError):
            result[0].title = "Changed"  # type: ignore[misc]

    def test_combined_severity_across_groups(self) -> None:
        related = [_SSH_NUCLEI, _SSH_NMAP, _SSH_NIKTO]
        result = _ENGINE.correlate(related)
        assert result[0].severity is Severity.HIGH

    def test_correlation_id_unique_per_group(self) -> None:
        result = _ENGINE.correlate([_SSH_NUCLEI, _WEB_NUCLEI])
        assert result[0].correlation_id != result[1].correlation_id


class TestOutputStability:
    def test_severity_descending_order(self) -> None:
        findings = [
            _make_nf(severity=Severity.LOW, references=("CVE-2024-0001",),
                     affected_assets=("10.0.0.1",)),
            _make_nf(severity=Severity.CRITICAL, references=("CVE-2025-0001",),
                     affected_assets=("10.0.0.2",)),
            _make_nf(severity=Severity.HIGH, references=("CVE-2026-0001",),
                     affected_assets=("10.0.0.3",)),
        ]
        result = _ENGINE.correlate(findings)
        for i in range(len(result) - 1):
            assert result[i].severity >= result[i + 1].severity

    def test_stable_across_multiple_calls(self) -> None:
        findings = [_SSH_NUCLEI, _SSH_NMAP, _WEB_NUCLEI]
        r1 = _ENGINE.correlate(findings)
        r2 = _ENGINE.correlate(findings)
        for i in range(len(r1)):
            assert r1[i].title == r2[i].title
            assert r1[i].scanner_sources == r2[i].scanner_sources
