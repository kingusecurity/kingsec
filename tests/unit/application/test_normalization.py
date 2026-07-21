"""Finding Normalization Engine: comprehensive tests for NormalizedFinding and FindingNormalizer."""

from __future__ import annotations

from datetime import UTC, datetime

import pytest

from kingsec.application.normalization import (
    FindingNormalizer,
    NormalizedFinding,
    classify_category,
    extract_affected_assets,
    extract_references,
    extract_tags,
)
from kingsec.domain import (
    Evidence,
    Finding,
    ScannerId,
    ScannerResult,
    Severity,
)

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _make_finding(
    title: str = "CVE-2024-1234 — SQL Injection",
    description: str = "SQL injection in /app/login via param username at 10.0.0.1",
    severity: Severity = Severity.HIGH,
    evidence_text: str = "Raw evidence detail",
) -> Finding:
    finding = Finding.create(title=title, description=description, severity=severity)
    finding.add_evidence(
        Evidence(
            summary="Evidence summary",
            detail=evidence_text,
            collected_at=datetime.now(UTC),
        )
    )
    return finding


def _make_result(
    findings: list[Finding] | None = None,
    scanner_id: str = "nuclei",
    scanner_version: str = "3.0.0",
) -> ScannerResult:
    return ScannerResult(
        scanner_id=ScannerId(scanner_id),
        findings=tuple(findings or [_make_finding()]),
        raw_output="",
        duration_seconds=1.0,
        scanner_version=scanner_version,
    )


# ===========================================================================
# NormalizedFinding construction
# ===========================================================================


class TestNormalizedFindingConstruction:
    """NormalizedFinding is a frozen dataclass with invariants."""

    def test_creates_with_valid_data(self) -> None:
        nf = NormalizedFinding(
            finding_id="find-123",
            title="Test",
            description="Desc",
            severity=Severity.HIGH,
            scanner_id="nuclei",
            scanner_version="3.0.0",
            evidence=(),
            recommendations=(),
            references=(),
            affected_assets=(),
            raw_data="raw",
            discovered_at=datetime.now(UTC),
            tags=(),
            category="vulnerability",
        )
        assert nf.finding_id == "find-123"
        assert nf.severity is Severity.HIGH

    def test_frozen_immutable(self) -> None:
        nf = NormalizedFinding(
            finding_id="find-123",
            title="Test",
            description="Desc",
            severity=Severity.LOW,
            scanner_id="nmap",
            scanner_version=None,
            evidence=(),
            recommendations=(),
            references=(),
            affected_assets=(),
            raw_data="",
            discovered_at=datetime.now(UTC),
            tags=(),
            category="information",
        )
        with pytest.raises(AttributeError):
            nf.title = "Changed"  # type: ignore[misc]

    def test_empty_finding_id_raises(self) -> None:
        with pytest.raises(ValueError, match="finding_id"):
            NormalizedFinding(
                finding_id="",
                title="Test",
                description="Desc",
                severity=Severity.LOW,
                scanner_id="nmap",
                scanner_version=None,
                evidence=(),
                recommendations=(),
                references=(),
                affected_assets=(),
                raw_data="",
                discovered_at=datetime.now(UTC),
                tags=(),
                category="information",
            )

    def test_empty_title_raises(self) -> None:
        with pytest.raises(ValueError, match="title"):
            NormalizedFinding(
                finding_id="find-123",
                title="",
                description="Desc",
                severity=Severity.LOW,
                scanner_id="nmap",
                scanner_version=None,
                evidence=(),
                recommendations=(),
                references=(),
                affected_assets=(),
                raw_data="",
                discovered_at=datetime.now(UTC),
                tags=(),
                category="information",
            )

    def test_non_severity_raises(self) -> None:
        with pytest.raises(TypeError, match="severity"):
            NormalizedFinding(
                finding_id="find-123",
                title="Test",
                description="Desc",
                severity="HIGH",  # type: ignore[arg-type]
                scanner_id="nmap",
                scanner_version=None,
                evidence=(),
                recommendations=(),
                references=(),
                affected_assets=(),
                raw_data="",
                discovered_at=datetime.now(UTC),
                tags=(),
                category="information",
            )


# ===========================================================================
# Extraction helpers
# ===========================================================================


class TestExtractReferences:
    def test_extracts_cve(self) -> None:
        refs = extract_references("Found CVE-2024-1234 in module")
        assert "CVE-2024-1234" in refs

    def test_extracts_url(self) -> None:
        refs = extract_references("See https://example.com/vuln for details")
        assert "https://example.com/vuln" in refs

    def test_extracts_multiple(self) -> None:
        refs = extract_references("CVE-2024-1111 and CVE-2024-2222 at https://a.com")
        assert len(refs) == 3

    def test_deduplicates(self) -> None:
        refs = extract_references("CVE-2024-1234 and CVE-2024-1234")
        assert len(refs) == 1

    def test_empty_text(self) -> None:
        refs = extract_references("")
        assert refs == ()

    def test_no_matches(self) -> None:
        refs = extract_references("no references here")
        assert refs == ()


class TestExtractAffectedAssets:
    def test_extracts_ip(self) -> None:
        assets = extract_affected_assets("Found at 10.0.0.1")
        assert "10.0.0.1" in assets

    def test_extracts_cidr(self) -> None:
        assets = extract_affected_assets("Network 192.168.1.0/24")
        assert "192.168.1.0/24" in assets

    def test_extracts_hostname(self) -> None:
        assets = extract_affected_assets("Host at mail.example.com is vulnerable")
        assert "mail.example.com" in assets

    def test_extracts_file_path(self) -> None:
        assets = extract_affected_assets("File /app/config/settings.py exposed")
        assert "/app/config/settings.py" in assets

    def test_extracts_multiple(self) -> None:
        assets = extract_affected_assets("10.0.0.1 and 10.0.0.2 and /etc/passwd")
        assert len(assets) == 3

    def test_deduplicates(self) -> None:
        assets = extract_affected_assets("10.0.0.1 and 10.0.0.1")
        assert len(assets) == 1

    def test_empty_text(self) -> None:
        assets = extract_affected_assets("")
        assert assets == ()


class TestExtractTags:
    def test_extracts_known_tags(self) -> None:
        tags = extract_tags("SQL injection vulnerability found")
        assert "injection" in tags
        assert "vulnerability" in tags

    def test_extracts_multiple(self) -> None:
        tags = extract_tags("XSS and CSRF vulnerabilities")
        assert "xss" in tags
        assert "csrf" in tags

    def test_empty_text(self) -> None:
        tags = extract_tags("")
        assert tags == ()

    def test_no_known_tags(self) -> None:
        tags = extract_tags("some random text without tags")
        assert tags == ()


class TestClassifyCategory:
    def test_vulnerability(self) -> None:
        cat = classify_category(Severity.HIGH, "SQL Injection", "injection in login")
        assert cat == "vulnerability"

    def test_misconfiguration(self) -> None:
        cat = classify_category(Severity.MEDIUM, "Missing Header", "X-Frame-Options missing")
        assert cat == "misconfiguration"

    def test_authentication(self) -> None:
        cat = classify_category(Severity.HIGH, "Hardcoded Password", "credential in config")
        assert cat == "authentication"

    def test_crypto(self) -> None:
        cat = classify_category(Severity.MEDIUM, "Weak TLS", "SSL/TLS configuration weak")
        assert cat == "crypto"

    def test_exposure(self) -> None:
        cat = classify_category(Severity.LOW, "Directory Listing", "backup directory exposed")
        assert cat == "exposure"

    def test_discovery(self) -> None:
        cat = classify_category(Severity.INFORMATIONAL, "Subdomain Found", "subdomain discovery")
        assert cat == "discovery"

    def test_information_fallback(self) -> None:
        cat = classify_category(Severity.INFORMATIONAL, "Server Banner", "nginx version disclosed")
        assert cat == "information"


# ===========================================================================
# FindingNormalizer
# ===========================================================================


class TestFindingNormalizerNormalize:
    """Core normalization behaviour."""

    def test_single_finding(self) -> None:
        normalizer = FindingNormalizer()
        result = _make_result()
        normalized = normalizer.normalize(result)
        assert len(normalized) == 1
        assert isinstance(normalized[0], NormalizedFinding)

    def test_preserves_finding_id(self) -> None:
        finding = _make_finding()
        finding_id = str(finding.id)
        result = _make_result(findings=[finding])
        normalizer = FindingNormalizer()
        normalized = normalizer.normalize(result)
        assert normalized[0].finding_id == finding_id

    def test_preserves_title(self) -> None:
        finding = _make_finding(title="My Title")
        result = _make_result(findings=[finding])
        normalizer = FindingNormalizer()
        normalized = normalizer.normalize(result)
        assert normalized[0].title == "My Title"

    def test_preserves_description(self) -> None:
        finding = _make_finding(description="My Description")
        result = _make_result(findings=[finding])
        normalizer = FindingNormalizer()
        normalized = normalizer.normalize(result)
        assert normalized[0].description == "My Description"

    def test_preserves_severity(self) -> None:
        finding = _make_finding(severity=Severity.CRITICAL)
        result = _make_result(findings=[finding])
        normalizer = FindingNormalizer()
        normalized = normalizer.normalize(result)
        assert normalized[0].severity is Severity.CRITICAL

    def test_preserves_evidence(self) -> None:
        finding = _make_finding(evidence_text="Important evidence")
        result = _make_result(findings=[finding])
        normalizer = FindingNormalizer()
        normalized = normalizer.normalize(result)
        assert len(normalized[0].evidence) == 1
        assert "Important evidence" in normalized[0].evidence[0].detail

    def test_preserves_scanner_id(self) -> None:
        result = _make_result(scanner_id="nmap")
        normalizer = FindingNormalizer()
        normalized = normalizer.normalize(result)
        assert normalized[0].scanner_id == "nmap"

    def test_preserves_scanner_version(self) -> None:
        result = _make_result(scanner_version="7.94")
        normalizer = FindingNormalizer()
        normalized = normalizer.normalize(result)
        assert normalized[0].scanner_version == "7.94"

    def test_raw_data_is_description(self) -> None:
        finding = _make_finding(description="The raw data")
        result = _make_result(findings=[finding])
        normalizer = FindingNormalizer()
        normalized = normalizer.normalize(result)
        assert normalized[0].raw_data == "The raw data"

    def test_extracts_references_from_description(self) -> None:
        finding = _make_finding(
            title="CVE-2024-1234",
            description="See https://example.com/advisory",
        )
        result = _make_result(findings=[finding])
        normalizer = FindingNormalizer()
        normalized = normalizer.normalize(result)
        assert "CVE-2024-1234" in normalized[0].references
        assert "https://example.com/advisory" in normalized[0].references

    def test_extracts_affected_assets(self) -> None:
        finding = _make_finding(description="Vulnerability at 10.0.0.1")
        result = _make_result(findings=[finding])
        normalizer = FindingNormalizer()
        normalized = normalizer.normalize(result)
        assert "10.0.0.1" in normalized[0].affected_assets

    def test_extracts_tags(self) -> None:
        finding = _make_finding(description="SQL injection vulnerability")
        result = _make_result(findings=[finding])
        normalizer = FindingNormalizer()
        normalized = normalizer.normalize(result)
        assert "injection" in normalized[0].tags
        assert "vulnerability" in normalized[0].tags

    def test_classifies_category(self) -> None:
        finding = _make_finding(title="SQL Injection", description="injection in login")
        result = _make_result(findings=[finding])
        normalizer = FindingNormalizer()
        normalized = normalizer.normalize(result)
        assert normalized[0].category == "vulnerability"

    def test_multiple_findings(self) -> None:
        findings = [
            _make_finding(title="Finding 1"),
            _make_finding(title="Finding 2"),
            _make_finding(title="Finding 3"),
        ]
        result = _make_result(findings=findings)
        normalizer = FindingNormalizer()
        normalized = normalizer.normalize(result)
        assert len(normalized) == 3


class TestFindingNormalizerNormalizeMany:
    """Multiple ScannerResult normalization."""

    def test_multiple_results(self) -> None:
        result1 = _make_result(
            findings=[_make_finding(title="From Nuclei")],
            scanner_id="nuclei",
        )
        result2 = _make_result(
            findings=[_make_finding(title="From Nmap")],
            scanner_id="nmap",
        )
        normalizer = FindingNormalizer()
        normalized = normalizer.normalize_many([result1, result2])
        assert len(normalized) == 2
        assert normalized[0].scanner_id == "nuclei"
        assert normalized[1].scanner_id == "nmap"

    def test_empty_results(self) -> None:
        normalizer = FindingNormalizer()
        normalized = normalizer.normalize_many([])
        assert normalized == []

    def test_preserves_order(self) -> None:
        result = _make_result(
            findings=[
                _make_finding(title="First"),
                _make_finding(title="Second"),
            ],
        )
        normalizer = FindingNormalizer()
        normalized = normalizer.normalize(result)
        assert normalized[0].title == "First"
        assert normalized[1].title == "Second"


class TestFindingNormalizerImmutability:
    """Normalized findings are immutable and independent."""

    def test_normalized_finding_is_frozen(self) -> None:
        normalizer = FindingNormalizer()
        result = _make_result()
        normalized = normalizer.normalize(result)
        with pytest.raises(AttributeError):
            normalized[0].title = "Changed"  # type: ignore[misc]

    def test_original_finding_unmodified(self) -> None:
        finding = _make_finding(title="Original")
        result = _make_result(findings=[finding])
        normalizer = FindingNormalizer()
        normalizer.normalize(result)
        assert finding.title == "Original"
