"""Finding Enrichment Engine: comprehensive tests."""

from __future__ import annotations

from datetime import datetime, timezone

import pytest

from kingsec.application.correlation import CorrelatedFinding
from kingsec.application.enrichment import EnrichedFinding, FindingEnricher
from kingsec.application.normalization import NormalizedFinding
from kingsec.domain import Evidence, Severity


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

_NOW = datetime.now(timezone.utc)

_ENGINE = FindingEnricher()


def _make_nf(
    title: str = "Generic Finding",
    description: str = "A generic security finding",
    severity: Severity = Severity.HIGH,
    scanner_id: str = "nuclei",
    tags: tuple[str, ...] = (),
) -> NormalizedFinding:
    return NormalizedFinding(
        finding_id=f"find-{title.lower().replace(' ', '-')[:16]}",
        title=title,
        description=description,
        severity=severity,
        scanner_id=scanner_id,
        scanner_version="3.0.0",
        evidence=(Evidence(summary="Evidence", detail="Detail", collected_at=_NOW),),
        recommendations=(),
        references=(),
        affected_assets=("10.0.0.1",),
        raw_data=description,
        discovered_at=_NOW,
        tags=tags,
        category="vulnerability",
    )


def _make_cf(
    correlation_id: str = "corr-abc123",
    title: str = "Security Finding",
    description: str = "A correlated security finding",
    severity: Severity = Severity.HIGH,
    category: str = "vulnerability",
    confidence: float = 0.60,
    scanner_sources: tuple[str, ...] = ("nuclei",),
    affected_assets: tuple[str, ...] = ("10.0.0.1",),
    references: tuple[str, ...] = ("CVE-2023-38408",),
    recommendations: tuple[str, ...] = (),
    tags: tuple[str, ...] = (),
    merged_finding: NormalizedFinding | None = None,
) -> CorrelatedFinding:
    if merged_finding is None:
        merged_finding = _make_nf()
    return CorrelatedFinding(
        correlation_id=correlation_id,
        title=title,
        severity=severity,
        category=category,
        affected_assets=affected_assets,
        references=references,
        scanner_sources=scanner_sources,
        merged_findings=(merged_finding,),
        confidence=confidence,
        description=description,
        recommendations=recommendations,
        tags=tags,
    )


# ===========================================================================
# EnrichedFinding construction
# ===========================================================================


class TestEnrichedFindingConstruction:
    def test_creates_with_valid_data(self) -> None:
        ef = EnrichedFinding(
            correlation_id="corr-abc",
            title="Test Issue",
            severity=Severity.HIGH,
            category="vulnerability",
            confidence=0.60,
            scanner_sources=("nuclei",),
            affected_assets=("10.0.0.1",),
            references=(),
            recommendations=(),
            tags=(),
            software=(),
            service=None,
            protocol=None,
            port=None,
            technology=(),
            operating_system=None,
            attack_surface=None,
            risk_factors=(),
            business_impact=None,
            exploit_likelihood=None,
            remediation_complexity=None,
            priority="Medium",
            metadata={},
            description="A test issue",
        )
        assert ef.correlation_id == "corr-abc"
        assert ef.title == "Test Issue"
        assert ef.severity == Severity.HIGH
        assert ef.priority == "Medium"

    def test_frozen_immutable(self) -> None:
        ef = EnrichedFinding(
            correlation_id="corr-abc",
            title="Test",
            severity=Severity.LOW,
            category="info",
            confidence=0.35,
            scanner_sources=("nmap",),
            affected_assets=("asset",),
            references=(),
            recommendations=(),
            tags=(),
            software=(),
            service=None,
            protocol=None,
            port=None,
            technology=(),
            operating_system=None,
            attack_surface=None,
            risk_factors=(),
            business_impact=None,
            exploit_likelihood=None,
            remediation_complexity=None,
            priority="Low",
            metadata={},
            description="Desc",
        )
        with pytest.raises(AttributeError):
            ef.title = "Changed"  # type: ignore[misc]

    def test_empty_correlation_id_raises(self) -> None:
        with pytest.raises(ValueError, match="correlation_id"):
            EnrichedFinding(
                correlation_id="",
                title="Test",
                severity=Severity.LOW,
                category="info",
                confidence=0.35,
                scanner_sources=("nmap",),
                affected_assets=(),
                references=(),
                recommendations=(),
                tags=(),
                software=(),
                service=None,
                protocol=None,
                port=None,
                technology=(),
                operating_system=None,
                attack_surface=None,
                risk_factors=(),
                business_impact=None,
                exploit_likelihood=None,
                remediation_complexity=None,
                priority="Low",
                metadata={},
                description="",
            )

    def test_empty_title_raises(self) -> None:
        with pytest.raises(ValueError, match="title"):
            EnrichedFinding(
                correlation_id="corr-abc",
                title="",
                severity=Severity.LOW,
                category="info",
                confidence=0.35,
                scanner_sources=("nmap",),
                affected_assets=(),
                references=(),
                recommendations=(),
                tags=(),
                software=(),
                service=None,
                protocol=None,
                port=None,
                technology=(),
                operating_system=None,
                attack_surface=None,
                risk_factors=(),
                business_impact=None,
                exploit_likelihood=None,
                remediation_complexity=None,
                priority="Low",
                metadata={},
                description="",
            )

    def test_confidence_out_of_range_raises(self) -> None:
        with pytest.raises(ValueError, match="confidence"):
            EnrichedFinding(
                correlation_id="corr-abc",
                title="Test",
                severity=Severity.LOW,
                category="info",
                confidence=1.5,
                scanner_sources=("nmap",),
                affected_assets=(),
                references=(),
                recommendations=(),
                tags=(),
                software=(),
                service=None,
                protocol=None,
                port=None,
                technology=(),
                operating_system=None,
                attack_surface=None,
                risk_factors=(),
                business_impact=None,
                exploit_likelihood=None,
                remediation_complexity=None,
                priority="Low",
                metadata={},
                description="",
            )

    def test_non_severity_raises(self) -> None:
        with pytest.raises(TypeError):
            EnrichedFinding(
                correlation_id="corr-abc",
                title="Test",
                severity="HIGH",  # type: ignore[arg-type]
                category="info",
                confidence=0.35,
                scanner_sources=("nmap",),
                affected_assets=(),
                references=(),
                recommendations=(),
                tags=(),
                software=(),
                service=None,
                protocol=None,
                port=None,
                technology=(),
                operating_system=None,
                attack_surface=None,
                risk_factors=(),
                business_impact=None,
                exploit_likelihood=None,
                remediation_complexity=None,
                priority="Low",
                metadata={},
                description="",
            )


# ===========================================================================
# Service detection
# ===========================================================================


class TestDetectService:
    def test_openssh_returns_ssh(self) -> None:
        cf = _make_cf(title="OpenSSH Vulnerability")
        assert _ENGINE.detect_service(cf) == "SSH"

    def test_ssh_returns_ssh(self) -> None:
        cf = _make_cf(title="SSH Server", description="SSH service")
        assert _ENGINE.detect_service(cf) == "SSH"

    def test_apache_returns_http(self) -> None:
        cf = _make_cf(title="Apache Vulnerability")
        assert _ENGINE.detect_service(cf) == "HTTP"

    def test_nginx_returns_http(self) -> None:
        cf = _make_cf(title="nginx misconfiguration")
        assert _ENGINE.detect_service(cf) == "HTTP"

    def test_iis_returns_http(self) -> None:
        cf = _make_cf(title="IIS Vulnerability")
        assert _ENGINE.detect_service(cf) == "HTTP"

    def test_mysql_returns_mysql(self) -> None:
        cf = _make_cf(title="MySQL Injection")
        assert _ENGINE.detect_service(cf) == "MySQL"

    def test_redis_returns_redis(self) -> None:
        cf = _make_cf(title="Redis Exposure")
        assert _ENGINE.detect_service(cf) == "Redis"

    def test_ftp_returns_ftp(self) -> None:
        cf = _make_cf(title="FTP anonymous access")
        assert _ENGINE.detect_service(cf) == "FTP"

    def test_dns_returns_dns(self) -> None:
        cf = _make_cf(title="DNS zone transfer")
        assert _ENGINE.detect_service(cf) == "DNS"

    def test_unknown_returns_none(self) -> None:
        cf = _make_cf(
            title="Generic Issue",
            description="A generic security finding with no known service",
            tags=(),
            merged_finding=_make_nf(
                title="Generic",
                description="No known software mentioned here",
                tags=(),
            ),
        )
        assert _ENGINE.detect_service(cf) is None

    def test_first_match_when_multiple_found(self) -> None:
        cf = _make_cf(title="OpenSSH and Apache")
        assert _ENGINE.detect_service(cf) == "SSH"

    def test_detects_from_merged_finding_description(self) -> None:
        nf = _make_nf(
            title="Some finding",
            description="postgresql listening on 5432",
            tags=(),
        )
        cf = _make_cf(
            title="Unrelated title",
            description="No direct mention",
            tags=(),
            merged_finding=nf,
        )
        assert _ENGINE.detect_service(cf) == "PostgreSQL"

    def test_detects_from_tags(self) -> None:
        cf = _make_cf(tags=("docker", "container"))
        assert _ENGINE.detect_service(cf) == "Docker"


# ===========================================================================
# Technology detection
# ===========================================================================


class TestDetectTechnology:
    def test_apache_returns_apache_http_server(self) -> None:
        cf = _make_cf(title="Apache mod_ssl vuln")
        tech = _ENGINE.detect_technology(cf)
        assert "Apache HTTP Server" in tech

    def test_nginx_returns_nginx(self) -> None:
        cf = _make_cf(title="nginx directory traversal")
        tech = _ENGINE.detect_technology(cf)
        assert "Nginx" in tech

    def test_iis_returns_microsoft_iis(self) -> None:
        cf = _make_cf(title="IIS vulnerability")
        tech = _ENGINE.detect_technology(cf)
        assert "Microsoft IIS" in tech

    def test_tomcat_returns_apache_tomcat(self) -> None:
        cf = _make_cf(title="Tomcat manager")
        tech = _ENGINE.detect_technology(cf)
        assert "Apache Tomcat" in tech

    def test_docker_returns_docker(self) -> None:
        cf = _make_cf(title="Docker misconfiguration")
        tech = _ENGINE.detect_technology(cf)
        assert "Docker" in tech

    def test_kubernetes_returns_kubernetes(self) -> None:
        cf = _make_cf(title="Kubernetes API exposure")
        tech = _ENGINE.detect_technology(cf)
        assert "Kubernetes" in tech

    def test_wordpress_returns_wordpress(self) -> None:
        cf = _make_cf(title="WordPress plugin vuln")
        tech = _ENGINE.detect_technology(cf)
        assert "WordPress" in tech

    def test_multiple_technologies(self) -> None:
        nf = _make_nf(
            title="Docker on Linux",
            description="Apache and PHP",
            tags=(),
        )
        cf = _make_cf(
            title="Full stack",
            description="Nginx reverse proxy",
            tags=(),
            merged_finding=nf,
        )
        tech = _ENGINE.detect_technology(cf)
        assert "Docker" in tech
        assert "PHP" in tech
        assert "Apache HTTP Server" in tech
        assert "Nginx" in tech

    def test_unknown_returns_empty(self) -> None:
        cf = _make_cf(
            title="Generic",
            description="Something unknown",
            tags=(),
            merged_finding=_make_nf(
                title="Generic",
                description="No known technology",
                tags=(),
            ),
        )
        assert _ENGINE.detect_technology(cf) == ()

    def test_dedup_duplicate_technologies(self) -> None:
        nf = _make_nf(
            title="apache and httpd both present",
            description="apache httpd",
            tags=(),
        )
        cf = _make_cf(
            title="apache httpd",
            description="",
            tags=(),
            merged_finding=nf,
        )
        tech = _ENGINE.detect_technology(cf)
        assert tech.count("Apache HTTP Server") == 1


# ===========================================================================
# Protocol detection
# ===========================================================================


class TestDetectProtocol:
    def test_ssh_returns_tcp(self) -> None:
        cf = _make_cf(title="SSH")
        assert _ENGINE.detect_protocol(cf) == "TCP"

    def test_http_returns_tcp(self) -> None:
        cf = _make_cf(title="HTTP")
        assert _ENGINE.detect_protocol(cf) == "TCP"

    def test_dns_returns_udp(self) -> None:
        cf = _make_cf(title="DNS")
        assert _ENGINE.detect_protocol(cf) == "UDP"

    def test_dhcp_returns_udp(self) -> None:
        cf = _make_cf(title="DHCP")
        assert _ENGINE.detect_protocol(cf) == "UDP"

    def test_kerberos_returns_tcp_udp(self) -> None:
        cf = _make_cf(title="Kerberos")
        assert _ENGINE.detect_protocol(cf) == "TCP/UDP"

    def test_unknown_returns_none(self) -> None:
        cf = _make_cf(
            title="Generic finding",
            description="No protocol mention",
            tags=(),
            merged_finding=_make_nf(
                title="Generic",
                description="Nothing known",
                tags=(),
            ),
        )
        assert _ENGINE.detect_protocol(cf) is None

    def test_first_match_when_multiple(self) -> None:
        cf = _make_cf(title="SSH and DNS")
        assert _ENGINE.detect_protocol(cf) == "TCP"


# ===========================================================================
# Port detection
# ===========================================================================


class TestDetectPort:
    def test_explicit_port_in_title(self) -> None:
        cf = _make_cf(title="Service on port 8080")
        assert _ENGINE.detect_port(cf) == 8080

    def test_explicit_port_in_description(self) -> None:
        cf = _make_cf(
            title="Service",
            description="Vulnerable service on port 8443",
        )
        assert _ENGINE.detect_port(cf) == 8443

    def test_explicit_port_with_colon(self) -> None:
        cf = _make_cf(
            title="Service",
            description="Found on 10.0.0.1:9090",
        )
        assert _ENGINE.detect_port(cf) == 9090

    def test_default_port_for_ssh_is_22(self) -> None:
        cf = _make_cf(
            title="SSH vulnerability",
            description="OpenSSH issue",
        )
        assert _ENGINE.detect_port(cf) == 22

    def test_default_port_for_http_is_80(self) -> None:
        cf = _make_cf(title="Apache issue")
        assert _ENGINE.detect_port(cf) == 80

    def test_default_port_for_https_is_443(self) -> None:
        cf = _make_cf(title="HTTPS certificate")
        assert _ENGINE.detect_port(cf) == 443

    def test_default_port_for_mysql_is_3306(self) -> None:
        cf = _make_cf(title="MySQL injection")
        assert _ENGINE.detect_port(cf) == 3306

    def test_explicit_port_precedes_default(self) -> None:
        cf = _make_cf(
            title="SSH on custom port",
            description="SSH service on port 2222",
        )
        assert _ENGINE.detect_port(cf) == 2222

    def test_unknown_returns_none(self) -> None:
        cf = _make_cf(
            title="Generic",
            description="A finding with no port or service",
            tags=(),
            merged_finding=_make_nf(
                title="Generic",
                description="Nothing identifiable",
                tags=(),
            ),
        )
        assert _ENGINE.detect_port(cf) is None


# ===========================================================================
# Operating system detection
# ===========================================================================


class TestDetectOperatingSystem:
    def test_windows_returns_microsoft_windows(self) -> None:
        cf = _make_cf(title="Windows vulnerability")
        assert _ENGINE.detect_operating_system(cf) == "Microsoft Windows"

    def test_linux_returns_linux(self) -> None:
        cf = _make_cf(title="Linux kernel issue")
        assert _ENGINE.detect_operating_system(cf) == "Linux"

    def test_ubuntu_returns_ubuntu_linux(self) -> None:
        cf = _make_cf(title="Ubuntu package update")
        assert _ENGINE.detect_operating_system(cf) == "Ubuntu Linux"

    def test_macos_returns_macos(self) -> None:
        cf = _make_cf(title="macOS vulnerability")
        assert _ENGINE.detect_operating_system(cf) == "macOS"

    def test_android_returns_android(self) -> None:
        cf = _make_cf(title="Android security patch")
        assert _ENGINE.detect_operating_system(cf) == "Android"

    def test_unknown_returns_none(self) -> None:
        cf = _make_cf(
            title="Generic",
            description="No OS mention",
            tags=(),
            merged_finding=_make_nf(
                title="Generic",
                description="Nothing identifiable",
                tags=(),
            ),
        )
        assert _ENGINE.detect_operating_system(cf) is None


# ===========================================================================
# Business impact estimation
# ===========================================================================


class TestEstimateBusinessImpact:
    def test_admin_returns_high(self) -> None:
        cf = _make_cf(title="Admin panel exposed")
        assert _ENGINE.estimate_business_impact(cf) == "High"

    def test_database_returns_critical(self) -> None:
        cf = _make_cf(title="Database exposed")
        assert _ENGINE.estimate_business_impact(cf) == "Critical"

    def test_ssh_returns_critical(self) -> None:
        cf = _make_cf(title="SSH vulnerability")
        assert _ENGINE.estimate_business_impact(cf) == "Critical"

    def test_authentication_bypass_returns_critical(self) -> None:
        cf = _make_cf(title="Authentication bypass")
        assert _ENGINE.estimate_business_impact(cf) == "Critical"

    def test_sensitive_data_returns_high(self) -> None:
        cf = _make_cf(title="Sensitive data exposure")
        assert _ENGINE.estimate_business_impact(cf) == "High"

    def test_injection_returns_critical(self) -> None:
        cf = _make_cf(title="SQL injection")
        assert _ENGINE.estimate_business_impact(cf) == "Critical"

    def test_path_traversal_returns_high(self) -> None:
        cf = _make_cf(title="Directory traversal")
        assert _ENGINE.estimate_business_impact(cf) == "High"

    def test_missing_header_returns_low(self) -> None:
        cf = _make_cf(
            title="Missing CSP header",
            description="missing header",
        )
        assert _ENGINE.estimate_business_impact(cf) == "Low"

    def test_discovery_returns_low(self) -> None:
        cf = _make_cf(
            title="Subdomain discovery",
            description="dns enumeration result",
        )
        assert _ENGINE.estimate_business_impact(cf) == "Low"

    def test_no_match_returns_none(self) -> None:
        cf = _make_cf(
            title="A very generic finding",
            description="Nothing matches any pattern",
            tags=(),
            merged_finding=_make_nf(
                title="Generic",
                description="Still nothing",
                tags=(),
            ),
        )
        assert _ENGINE.estimate_business_impact(cf) is None


# ===========================================================================
# Exploit likelihood estimation
# ===========================================================================


class TestEstimateExploitLikelihood:
    def test_critical_with_high_confidence_returns_high(self) -> None:
        cf = _make_cf(severity=Severity.CRITICAL, confidence=0.80)
        assert _ENGINE.estimate_exploit_likelihood(cf) == "High"

    def test_critical_with_low_confidence_returns_medium(self) -> None:
        cf = _make_cf(severity=Severity.CRITICAL, confidence=0.35)
        assert _ENGINE.estimate_exploit_likelihood(cf) == "Medium"

    def test_high_with_high_confidence_returns_high(self) -> None:
        cf = _make_cf(severity=Severity.HIGH, confidence=0.80)
        assert _ENGINE.estimate_exploit_likelihood(cf) == "High"

    def test_high_with_low_confidence_returns_medium(self) -> None:
        cf = _make_cf(severity=Severity.HIGH, confidence=0.35)
        assert _ENGINE.estimate_exploit_likelihood(cf) == "Medium"

    def test_medium_returns_medium(self) -> None:
        cf = _make_cf(severity=Severity.MEDIUM)
        assert _ENGINE.estimate_exploit_likelihood(cf) == "Medium"

    def test_low_returns_low(self) -> None:
        cf = _make_cf(severity=Severity.LOW)
        assert _ENGINE.estimate_exploit_likelihood(cf) == "Low"

    def test_informational_returns_low(self) -> None:
        cf = _make_cf(severity=Severity.INFORMATIONAL)
        assert _ENGINE.estimate_exploit_likelihood(cf) == "Low"


# ===========================================================================
# Remediation complexity estimation
# ===========================================================================


class TestEstimateRemediationComplexity:
    def test_missing_header_returns_easy(self) -> None:
        cf = _make_cf(title="Missing CSP header")
        assert _ENGINE.estimate_remediation_complexity(cf) == "Easy"

    def test_upgrade_returns_medium(self) -> None:
        cf = _make_cf(title="Upgrade required")
        assert _ENGINE.estimate_remediation_complexity(cf) == "Medium"

    def test_patch_returns_medium(self) -> None:
        cf = _make_cf(title="Security patch needed")
        assert _ENGINE.estimate_remediation_complexity(cf) == "Medium"

    def test_infrastructure_returns_hard(self) -> None:
        cf = _make_cf(title="Redesign required")
        assert _ENGINE.estimate_remediation_complexity(cf) == "Hard"

    def test_firewall_returns_hard(self) -> None:
        cf = _make_cf(title="Firewall reconfiguration")
        assert _ENGINE.estimate_remediation_complexity(cf) == "Hard"

    def test_certificate_returns_medium(self) -> None:
        cf = _make_cf(title="Expired SSL certificate")
        assert _ENGINE.estimate_remediation_complexity(cf) == "Medium"

    def test_no_match_returns_none(self) -> None:
        cf = _make_cf(
            title="A finding with no remediation keywords",
            description="Nothing matches",
            tags=(),
            merged_finding=_make_nf(
                title="Still nothing",
                description="No match at all",
                tags=(),
            ),
        )
        assert _ENGINE.estimate_remediation_complexity(cf) is None

    def test_remove_returns_easy(self) -> None:
        cf = _make_cf(title="Remove insecure endpoint")
        assert _ENGINE.estimate_remediation_complexity(cf) == "Easy"


# ===========================================================================
# Priority calculation
# ===========================================================================


class TestCalculatePriority:
    def test_critical_returns_critical(self) -> None:
        cf = _make_cf(severity=Severity.CRITICAL, confidence=1.0,
                       description="critical database vulnerability")
        assert _ENGINE.calculate_priority(cf) == "Critical"

    def test_informational_returns_low(self) -> None:
        cf = _make_cf(severity=Severity.INFORMATIONAL, confidence=0.35,
                       description="banner info")
        assert _ENGINE.calculate_priority(cf) == "Low"

    def test_high_with_good_confidence_returns_high(self) -> None:
        cf = _make_cf(severity=Severity.HIGH, confidence=0.80,
                       title="Security issue no impact keywords")
        assert _ENGINE.calculate_priority(cf) == "High"

    def test_boundary_80_is_critical(self) -> None:
        cf = _make_cf(severity=Severity.CRITICAL, confidence=1.0,
                       title="Web server issue medium business impact")
        assert _ENGINE.calculate_priority(cf) == "Critical"

    def test_boundary_79_is_high(self) -> None:
        cf = _make_cf(severity=Severity.CRITICAL, confidence=0.80,
                       title="Discovery info low impact")
        assert _ENGINE.calculate_priority(cf) == "High"

    def test_boundary_60_is_high(self) -> None:
        cf = _make_cf(severity=Severity.HIGH, confidence=0.80,
                       title="A finding with no business impact keywords")
        assert _ENGINE.calculate_priority(cf) == "High"

    def test_boundary_59_is_medium(self) -> None:
        cf = _make_cf(severity=Severity.HIGH, confidence=0.60,
                       title="No business impact keywords here")
        assert _ENGINE.calculate_priority(cf) == "Medium"

    def test_deterministic(self) -> None:
        cf = _make_cf()
        assert _ENGINE.calculate_priority(cf) == _ENGINE.calculate_priority(cf)


# ===========================================================================
# enrich_one
# ===========================================================================


class TestEnrichOne:
    def test_returns_enriched_finding(self) -> None:
        cf = _make_cf()
        result = _ENGINE.enrich_one(cf)
        assert isinstance(result, EnrichedFinding)

    def test_preserves_all_correlated_fields(self) -> None:
        cf = _make_cf(
            correlation_id="corr-preserve",
            title="Preserve Title",
            description="Preserve Desc",
            severity=Severity.MEDIUM,
            category="misconfiguration",
            confidence=0.80,
            scanner_sources=("nuclei", "nmap"),
            affected_assets=("10.0.0.1", "10.0.0.2"),
            references=("CVE-2024-0001",),
            recommendations=("Fix it",),
            tags=("test",),
        )
        result = _ENGINE.enrich_one(cf)
        assert result.correlation_id == "corr-preserve"
        assert result.title == "Preserve Title"
        assert result.description == "Preserve Desc"
        assert result.severity == Severity.MEDIUM
        assert result.category == "misconfiguration"
        assert result.confidence == 0.80
        assert result.scanner_sources == ("nuclei", "nmap")
        assert result.affected_assets == ("10.0.0.1", "10.0.0.2")
        assert result.references == ("CVE-2024-0001",)
        assert result.recommendations == ("Fix it",)
        assert result.tags == ("test",)

    def test_populates_software(self) -> None:
        cf = _make_cf(
            title="OpenSSH and Apache and MySQL",
            description="Multiple software mentions",
        )
        result = _ENGINE.enrich_one(cf)
        assert "openssh" in result.software
        assert "apache" in result.software
        assert "mysql" in result.software

    def test_populates_metadata(self) -> None:
        cf = _make_cf(
            title="SSH vulnerability on Ubuntu",
            description="port 22",
        )
        result = _ENGINE.enrich_one(cf)
        assert result.metadata["detected_service"] == "SSH"
        assert result.metadata["detected_protocol"] == "TCP"
        assert result.metadata["detected_port"] == "22"
        assert result.metadata["detected_os"] == "Ubuntu Linux"

    def test_attack_surface_in_metadata(self) -> None:
        cf = _make_cf(title="Apache HTTP vulnerability")
        result = _ENGINE.enrich_one(cf)
        assert result.metadata["detected_attack_surface"] == "Web Application"

    def test_deterministic_output(self) -> None:
        cf = _make_cf()
        r1 = _ENGINE.enrich_one(cf)
        r2 = _ENGINE.enrich_one(cf)
        assert r1 == r2

    def test_empty_tags_dont_cause_errors(self) -> None:
        cf = _make_cf(tags=(), merged_finding=_make_nf(tags=()))
        result = _ENGINE.enrich_one(cf)
        assert isinstance(result, EnrichedFinding)


# ===========================================================================
# enrich
# ===========================================================================


class TestEnrich:
    def test_empty_input_returns_empty_list(self) -> None:
        assert _ENGINE.enrich([]) == []

    def test_multiple_findings(self) -> None:
        cf1 = _make_cf(
            correlation_id="corr-1",
            title="SSH issue",
            description="OpenSSH vulnerability",
        )
        cf2 = _make_cf(
            correlation_id="corr-2",
            title="Apache issue",
            description="Apache mod_ssl",
        )
        results = _ENGINE.enrich([cf1, cf2])
        assert len(results) == 2
        assert results[0].correlation_id == "corr-1"
        assert results[1].correlation_id == "corr-2"

    def test_maintains_input_order(self) -> None:
        cf1 = _make_cf(correlation_id="corr-z")
        cf2 = _make_cf(correlation_id="corr-a")
        cf3 = _make_cf(correlation_id="corr-m")
        results = _ENGINE.enrich([cf1, cf2, cf3])
        assert [r.correlation_id for r in results] == ["corr-z", "corr-a", "corr-m"]

    def test_deterministic_output(self) -> None:
        findings = [
            _make_cf(correlation_id="corr-1"),
            _make_cf(correlation_id="corr-2"),
        ]
        r1 = _ENGINE.enrich(findings)
        r2 = _ENGINE.enrich(findings)
        assert r1 == r2


# ===========================================================================
# Risk factors
# ===========================================================================


class TestRiskFactors:
    def test_remote_exploitable(self) -> None:
        cf = _make_cf(title="Remote code execution")
        result = _ENGINE.enrich_one(cf)
        assert "Remote Code Execution" in result.risk_factors

    def test_credential_exposure(self) -> None:
        cf = _make_cf(title="Password in plaintext")
        result = _ENGINE.enrich_one(cf)
        assert "Credential Exposure" in result.risk_factors

    def test_injection(self) -> None:
        cf = _make_cf(title="SQL injection vulnerability")
        result = _ENGINE.enrich_one(cf)
        assert "Injection" in result.risk_factors

    def test_information_disclosure(self) -> None:
        cf = _make_cf(title="Information disclosure")
        result = _ENGINE.enrich_one(cf)
        assert "Information Disclosure" in result.risk_factors

    def test_multiple_risk_factors(self) -> None:
        cf = _make_cf(
            title="Remote code execution via SQL injection",
            description="Exposed credential on public server",
        )
        result = _ENGINE.enrich_one(cf)
        assert "Remote Code Execution" in result.risk_factors
        assert "Injection" in result.risk_factors
        assert "Credential Exposure" in result.risk_factors
        assert "Remote Exploitable" in result.risk_factors

    def test_no_risk_factors_returns_empty(self) -> None:
        cf = _make_cf(
            title="Nothing risky here",
            description="A completely benign finding",
            tags=(),
            merged_finding=_make_nf(
                title="Benign",
                description="No risk keywords",
                tags=(),
            ),
        )
        result = _ENGINE.enrich_one(cf)
        assert result.risk_factors == ()


# ===========================================================================
# Attack surface
# ===========================================================================


class TestAttackSurface:
    def test_web_application(self) -> None:
        cf = _make_cf(title="XSS vulnerability")
        result = _ENGINE.enrich_one(cf)
        assert result.attack_surface == "Web Application"

    def test_network_service(self) -> None:
        cf = _make_cf(title="SSH brute force")
        result = _ENGINE.enrich_one(cf)
        assert result.attack_surface == "Network Service"

    def test_database(self) -> None:
        cf = _make_cf(title="MySQL injection")
        result = _ENGINE.enrich_one(cf)
        assert result.attack_surface == "Database"

    def test_api(self) -> None:
        cf = _make_cf(title="REST API endpoint exposed")
        result = _ENGINE.enrich_one(cf)
        assert result.attack_surface == "API"

    def test_dns(self) -> None:
        cf = _make_cf(title="DNS zone transfer")
        result = _ENGINE.enrich_one(cf)
        assert result.attack_surface == "DNS"

    def test_container(self) -> None:
        cf = _make_cf(title="Docker misconfiguration")
        result = _ENGINE.enrich_one(cf)
        assert result.attack_surface == "Container"

    def test_file_system(self) -> None:
        cf = _make_cf(title="Directory traversal")
        result = _ENGINE.enrich_one(cf)
        assert result.attack_surface == "File System"


# ===========================================================================
# Edge cases
# ===========================================================================


class TestEdgeCases:
    def test_minimal_finding(self) -> None:
        nf = _make_nf(title="Minimal", description="tiny", tags=())
        cf = _make_cf(
            correlation_id="corr-min",
            title="Min",
            description="small",
            severity=Severity.LOW,
            confidence=0.35,
            scanner_sources=("nmap",),
            affected_assets=("host",),
            references=(),
            recommendations=(),
            tags=(),
            merged_finding=nf,
        )
        result = _ENGINE.enrich_one(cf)
        assert result.correlation_id == "corr-min"
        assert result.service is None
        assert result.technology == ()
        assert result.operating_system is None
        assert result.risk_factors == ()

    def test_large_dataset(self) -> None:
        findings = [
            _make_cf(
                correlation_id=f"corr-{i:04d}",
                title=f"Finding {i}",
                description=f"OpenSSH issue on host 10.0.0.{i % 10}",
                severity=Severity.MEDIUM,
                confidence=0.60,
            )
            for i in range(50)
        ]
        results = _ENGINE.enrich(findings)
        assert len(results) == 50
        for r in results:
            assert isinstance(r, EnrichedFinding)
            assert r.service == "SSH"
            assert r.protocol == "TCP"
            assert r.port == 22

    def test_different_scanner_sources(self) -> None:
        cf = _make_cf(
            scanner_sources=("nuclei", "nmap", "nikto"),
            confidence=0.80,
        )
        r = _ENGINE.enrich_one(cf)
        assert r.scanner_sources == ("nuclei", "nmap", "nikto")
        assert r.confidence == 0.80

    def test_port_is_integer_not_string(self) -> None:
        cf = _make_cf(description="Found on port 443")
        r = _ENGINE.enrich_one(cf)
        assert isinstance(r.port, int)
        assert r.port == 443
        assert r.metadata["detected_port"] == "443"

    def test_software_never_empty_for_known_finding(self) -> None:
        cf = _make_cf(title="OpenSSH CVE-2023-38408")
        r = _ENGINE.enrich_one(cf)
        assert len(r.software) > 0
