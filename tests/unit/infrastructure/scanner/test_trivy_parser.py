"""Trivy parser: comprehensive tests for parse_trivy_json."""

from __future__ import annotations

import json

import pytest

from kingsec.domain import Severity
from kingsec.infrastructure.scanner.errors import ScannerOutputError
from kingsec.infrastructure.scanner.trivy_parser import parse_trivy_json

# ---------------------------------------------------------------------------
# Fixtures: sample Trivy JSON outputs
# ---------------------------------------------------------------------------

_EMPTY_OUTPUT = ""

_EMPTY_RESULTS = json.dumps({"Results": []})

_NO_RESULTS_KEY = json.dumps({})


def _make_vuln_result(
    target: str = "/app",
    vulns: list[dict] | None = None,
) -> dict:
    """Build a Trivy result dict with vulnerabilities."""
    return {
        "Target": target,
        "Class": "lang-pkgs",
        "Vulnerabilities": vulns or [],
    }


def _make_misconfig_result(
    target: str = "/app/config.yaml",
    misconfigs: list[dict] | None = None,
) -> dict:
    """Build a Trivy result dict with misconfigurations."""
    return {
        "Target": target,
        "Class": "config",
        "Misconfigurations": misconfigs or [],
    }


_VULN_RECORD = {
    "VulnerabilityID": "CVE-2024-1234",
    "PkgName": "openssl",
    "InstalledVersion": "1.1.1",
    "FixedVersion": "1.1.2",
    "Severity": "HIGH",
    "Title": "OpenSSL Vulnerability",
    "Description": "A vulnerability in OpenSSL",
}

_VULN_RECORD_LOW = {
    "VulnerabilityID": "CVE-2024-5678",
    "PkgName": "libxml2",
    "InstalledVersion": "2.9.0",
    "FixedVersion": "",
    "Severity": "LOW",
    "Title": "Libxml2 Issue",
    "Description": "A minor issue in libxml2",
}

_VULN_RECORD_CRITICAL = {
    "VulnerabilityID": "CVE-2024-9999",
    "PkgName": "log4j",
    "InstalledVersion": "2.14.0",
    "FixedVersion": "2.17.0",
    "Severity": "CRITICAL",
    "Title": "Log4Shell",
    "Description": "Remote code execution in Log4j",
}

_VULN_RECORD_UNKNOWN = {
    "VulnerabilityID": "CVE-2024-0000",
    "PkgName": "mystery",
    "InstalledVersion": "1.0.0",
    "FixedVersion": "",
    "Severity": "UNKNOWN",
    "Title": "Unknown Issue",
    "Description": "Unknown severity",
}

_MISCONFIG_RECORD = {
    "ID": "DS002",
    "Severity": "MEDIUM",
    "Title": "SSH Daemon Configuration",
    "Message": "SSH protocol 1 is enabled",
    "Resolution": "Disable SSH protocol 1",
}

_MISCONFIG_RECORD_HIGH = {
    "ID": "DS001",
    "Severity": "HIGH",
    "Title": "Firewall Disabled",
    "Message": "Firewall is not enabled",
    "Resolution": "Enable the firewall",
}

_FULL_VULN_OUTPUT = json.dumps(
    {
        "Results": [
            _make_vuln_result("/app", [_VULN_RECORD, _VULN_RECORD_LOW]),
            _make_vuln_result("/usr/lib", [_VULN_RECORD_CRITICAL]),
        ]
    }
)

_FULL_MISCONFIG_OUTPUT = json.dumps(
    {
        "Results": [
            _make_misconfig_result("/app/config.yaml", [_MISCONFIG_RECORD]),
            _make_misconfig_result("/etc/ssh/sshd_config", [_MISCONFIG_RECORD_HIGH]),
        ]
    }
)

_FULL_MIXED_OUTPUT = json.dumps(
    {
        "Results": [
            _make_vuln_result("/app", [_VULN_RECORD]),
            _make_misconfig_result("/app/config.yaml", [_MISCONFIG_RECORD]),
        ]
    }
)

_MALFORMED_JSON = "this is not json"


# ===========================================================================
# Tests
# ===========================================================================


class TestParseTrivyJson:
    """Core parser behaviour."""

    def test_empty_output_is_not_a_valid_trivy_report(self) -> None:
        with pytest.raises(ScannerOutputError):
            parse_trivy_json(_EMPTY_OUTPUT)

    def test_malformed_json_raises_output_error(self) -> None:
        with pytest.raises(ScannerOutputError):
            parse_trivy_json(_MALFORMED_JSON)

    def test_empty_results(self) -> None:
        assert parse_trivy_json(_EMPTY_RESULTS) == []

    def test_no_results_key_raises_output_error(self) -> None:
        with pytest.raises(ScannerOutputError):
            parse_trivy_json(_NO_RESULTS_KEY)

    def test_non_object_report_raises_output_error(self) -> None:
        with pytest.raises(ScannerOutputError):
            parse_trivy_json(json.dumps([]))

    def test_non_array_results_raises_output_error(self) -> None:
        with pytest.raises(ScannerOutputError):
            parse_trivy_json(json.dumps({"Results": {}}))

    def test_single_vulnerability(self) -> None:
        output = json.dumps({"Results": [_make_vuln_result("/app", [_VULN_RECORD])]})
        findings = parse_trivy_json(output)
        assert len(findings) == 1
        assert "CVE-2024-1234" in findings[0].title
        assert "openssl" in findings[0].title

    def test_multiple_vulnerabilities(self) -> None:
        findings = parse_trivy_json(_FULL_VULN_OUTPUT)
        assert len(findings) == 3

    def test_single_misconfiguration(self) -> None:
        output = json.dumps({"Results": [_make_misconfig_result("/app", [_MISCONFIG_RECORD])]})
        findings = parse_trivy_json(output)
        assert len(findings) == 1
        assert "DS002" in findings[0].title

    def test_multiple_misconfigurations(self) -> None:
        findings = parse_trivy_json(_FULL_MISCONFIG_OUTPUT)
        assert len(findings) == 2

    def test_mixed_vulns_and_misconfigs(self) -> None:
        findings = parse_trivy_json(_FULL_MIXED_OUTPUT)
        assert len(findings) == 2

    def test_non_dict_results_raise_output_error(self) -> None:
        output = json.dumps({"Results": ["not a dict", 123]})
        with pytest.raises(ScannerOutputError):
            parse_trivy_json(output)

    def test_result_without_target_raises_output_error(self) -> None:
        output = json.dumps({"Results": [{"Vulnerabilities": [], "Misconfigurations": []}]})
        with pytest.raises(ScannerOutputError):
            parse_trivy_json(output)

    def test_non_array_finding_collection_raises_output_error(self) -> None:
        output = json.dumps({"Results": [{"Target": "/app", "Vulnerabilities": {}}]})
        with pytest.raises(ScannerOutputError):
            parse_trivy_json(output)

    def test_empty_vulns_and_misconfigs(self) -> None:
        output = json.dumps({"Results": [{"Target": "/app", "Vulnerabilities": [], "Misconfigurations": []}]})
        assert parse_trivy_json(output) == []


class TestSeverityClassification:
    """Severity mapping for different Trivy severity levels."""

    def test_critical_maps_to_critical(self) -> None:
        output = json.dumps({"Results": [_make_vuln_result("/app", [_VULN_RECORD_CRITICAL])]})
        findings = parse_trivy_json(output)
        assert findings[0].severity is Severity.CRITICAL

    def test_high_maps_to_high(self) -> None:
        output = json.dumps({"Results": [_make_vuln_result("/app", [_VULN_RECORD])]})
        findings = parse_trivy_json(output)
        assert findings[0].severity is Severity.HIGH

    def test_low_maps_to_low(self) -> None:
        output = json.dumps({"Results": [_make_vuln_result("/app", [_VULN_RECORD_LOW])]})
        findings = parse_trivy_json(output)
        assert findings[0].severity is Severity.LOW

    def test_unknown_maps_to_informational(self) -> None:
        output = json.dumps({"Results": [_make_vuln_result("/app", [_VULN_RECORD_UNKNOWN])]})
        findings = parse_trivy_json(output)
        assert findings[0].severity is Severity.INFORMATIONAL

    def test_misconfig_severity_medium(self) -> None:
        output = json.dumps({"Results": [_make_misconfig_result("/app", [_MISCONFIG_RECORD])]})
        findings = parse_trivy_json(output)
        assert findings[0].severity is Severity.MEDIUM

    def test_misconfig_severity_high(self) -> None:
        output = json.dumps({"Results": [_make_misconfig_result("/app", [_MISCONFIG_RECORD_HIGH])]})
        findings = parse_trivy_json(output)
        assert findings[0].severity is Severity.HIGH


class TestEvidence:
    """Evidence is attached to every finding."""

    def test_vuln_findings_have_evidence(self) -> None:
        output = json.dumps({"Results": [_make_vuln_result("/app", [_VULN_RECORD])]})
        findings = parse_trivy_json(output)
        assert len(findings[0].evidence) == 1
        assert "Trivy:" in findings[0].evidence[0].summary

    def test_misconfig_findings_have_evidence(self) -> None:
        output = json.dumps({"Results": [_make_misconfig_result("/app", [_MISCONFIG_RECORD])]})
        findings = parse_trivy_json(output)
        assert len(findings[0].evidence) == 1
        assert "Trivy misconfig:" in findings[0].evidence[0].summary

    def test_vuln_description_contains_fixed_version(self) -> None:
        output = json.dumps({"Results": [_make_vuln_result("/app", [_VULN_RECORD])]})
        findings = parse_trivy_json(output)
        assert "1.1.2" in findings[0].description

    def test_vuln_description_no_fixed_version(self) -> None:
        output = json.dumps({"Results": [_make_vuln_result("/app", [_VULN_RECORD_LOW])]})
        findings = parse_trivy_json(output)
        assert "none" in findings[0].description


class TestCveCvss:
    """CVE ID, CWE IDs, and CVSS score/vector on the resulting Finding.

    Fixture shapes mirror real Trivy output captured live against this
    repo's own frontend/ npm dependencies (react-router CVEs), including a
    genuine cross-source CVSS disagreement, to make sure the preference
    order is exercised against realistic data, not an invented shape.
    """

    def test_cve_id_becomes_structured_field(self) -> None:
        output = json.dumps({"Results": [_make_vuln_result("/app", [_VULN_RECORD])]})
        findings = parse_trivy_json(output)
        assert findings[0].cve_ids == ("CVE-2024-1234",)

    def test_no_vulnerability_id_means_no_cve_ids(self) -> None:
        record = {k: v for k, v in _VULN_RECORD.items() if k != "VulnerabilityID"}
        output = json.dumps({"Results": [_make_vuln_result("/app", [record])]})
        findings = parse_trivy_json(output)
        assert findings[0].cve_ids == ()

    def test_cwe_ids_extracted(self) -> None:
        record = {**_VULN_RECORD, "CweIDs": ["CWE-470"]}
        output = json.dumps({"Results": [_make_vuln_result("/app", [record])]})
        findings = parse_trivy_json(output)
        assert findings[0].cwe_ids == ("CWE-470",)

    def test_no_cwe_ids_field_means_empty_tuple(self) -> None:
        output = json.dumps({"Results": [_make_vuln_result("/app", [_VULN_RECORD])]})
        findings = parse_trivy_json(output)
        assert findings[0].cwe_ids == ()

    def test_misconfig_never_carries_cve_data(self) -> None:
        """Misconfigurations (e.g. DS002) are not CVEs - Trivy doesn't shape
        them that way, and this parser must not invent CVE data for them."""
        output = json.dumps({"Results": [_make_misconfig_result("/app", [_MISCONFIG_RECORD])]})
        findings = parse_trivy_json(output)
        assert findings[0].cve_ids == ()
        assert findings[0].cvss_score is None

    def test_single_source_cvss_used_directly(self) -> None:
        record = {
            **_VULN_RECORD,
            "CVSS": {"nvd": {"V3Vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N", "V3Score": 6.1}},
        }
        output = json.dumps({"Results": [_make_vuln_result("/app", [record])]})
        findings = parse_trivy_json(output)
        assert findings[0].cvss_score == 6.1
        assert findings[0].cvss_vector == "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N"

    def test_source_preference_nvd_over_redhat_over_ghsa(self) -> None:
        """Real disagreement captured live: the same CVE scored 6.1 by NVD,
        5.4 by RedHat, and (CVSS 4.0 only) 5.1 by GHSA. NVD must win."""
        record = {
            **_VULN_RECORD,
            "CVSS": {
                "ghsa": {"V40Vector": "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:A/VC:N/VI:L/VA:N/SC:L/SI:L/SA:N", "V40Score": 5.1},
                "nvd": {"V3Vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N", "V3Score": 6.1},
                "redhat": {"V3Vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:L/I:L/A:N", "V3Score": 5.4},
            },
        }
        output = json.dumps({"Results": [_make_vuln_result("/app", [record])]})
        findings = parse_trivy_json(output)
        assert findings[0].cvss_score == 6.1
        assert findings[0].cvss_vector == "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N"

    def test_falls_through_to_next_preferred_source_when_top_choice_absent(self) -> None:
        """Only ghsa and redhat present (no nvd) - redhat must win, not ghsa,
        per the NVD > RedHat > GHSA preference order."""
        record = {
            **_VULN_RECORD,
            "CVSS": {
                "ghsa": {"V3Vector": "CVSS:3.1/AV:N/AC:H/PR:N/UI:R/S:C/C:H/I:L/A:N", "V3Score": 6.9},
                "redhat": {"V3Vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:L/I:L/A:N", "V3Score": 5.4},
            },
        }
        output = json.dumps({"Results": [_make_vuln_result("/app", [record])]})
        findings = parse_trivy_json(output)
        assert findings[0].cvss_score == 5.4
        assert findings[0].cvss_vector == "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:L/I:L/A:N"

    def test_cvss_31_preferred_over_40_within_same_source(self) -> None:
        record = {
            **_VULN_RECORD,
            "CVSS": {
                "nvd": {
                    "V3Vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N",
                    "V3Score": 6.1,
                    "V40Vector": "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:A/VC:N/VI:L/VA:N/SC:L/SI:L/SA:N",
                    "V40Score": 5.1,
                },
            },
        }
        output = json.dumps({"Results": [_make_vuln_result("/app", [record])]})
        findings = parse_trivy_json(output)
        assert findings[0].cvss_score == 6.1

    def test_no_cvss_field_at_all_means_no_score(self) -> None:
        output = json.dumps({"Results": [_make_vuln_result("/app", [_VULN_RECORD])]})
        findings = parse_trivy_json(output)
        assert findings[0].cvss_score is None
        assert findings[0].cvss_vector is None

    def test_malformed_cvss_shape_raises_output_error(self) -> None:
        record = {**_VULN_RECORD, "CVSS": "not a dict"}
        output = json.dumps({"Results": [_make_vuln_result("/app", [record])]})
        with pytest.raises(ScannerOutputError):
            parse_trivy_json(output)


class TestRecommendations:
    """Resolution → Recommendation mapping for misconfigurations."""

    def test_misconfig_resolution_becomes_recommendation(self) -> None:
        output = json.dumps({"Results": [_make_misconfig_result("/app", [_MISCONFIG_RECORD])]})
        findings = parse_trivy_json(output)
        assert len(findings[0].recommendations) == 1
        assert findings[0].recommendations[0].description == "Disable SSH protocol 1"

    def test_misconfig_without_resolution_has_no_recommendation(self) -> None:
        record = {k: v for k, v in _MISCONFIG_RECORD.items() if k != "Resolution"}
        output = json.dumps({"Results": [_make_misconfig_result("/app", [record])]})
        findings = parse_trivy_json(output)
        assert len(findings[0].recommendations) == 0
