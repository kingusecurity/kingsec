"""Amass parser: comprehensive tests for parse_amass_json."""

from __future__ import annotations

import json

from kingsec.domain import Severity
from kingsec.infrastructure.scanner.amass_parser import parse_amass_json

# ---------------------------------------------------------------------------
# Fixtures: sample Amass JSON outputs
# ---------------------------------------------------------------------------

_EMPTY_OUTPUT = ""


def _make_record(
    name: str = "sub.example.com",
    domain: str = "example.com",
    addresses: list[dict[str, str]] | None = None,
    sources: list[str] | None = None,
    tag: str = "subdomain",
) -> str:
    """Build a single-line Amass JSON record."""
    record = {
        "name": name,
        "domain": domain,
        "addresses": addresses or [{"ip": "10.0.0.1", "cidr": "10.0.0.0/24"}],
        "sources": sources or ["DNS"],
        "tag": tag,
    }
    return json.dumps(record)


_FULL_ENUM_OUTPUT = "\n".join([
    _make_record("www.example.com", "example.com", [{"ip": "10.0.0.1"}], ["DNS"], "subdomain"),
    _make_record("mail.example.com", "example.com", [{"ip": "10.0.0.2"}], ["DNS", "Cert"], "subdomain"),
    _make_record("admin.example.com", "example.com", [{"ip": "10.0.0.3"}], ["DNS"], "subdomain"),
    _make_record("vpn.example.com", "example.com", [{"ip": "10.0.0.4"}], ["DNS"], "subdomain"),
    _make_record("api.example.com", "example.com", [{"ip": "10.0.0.5"}], ["DNS"], "subdomain"),
    _make_record("backup.example.com", "example.com", [{"ip": "10.0.0.6"}], ["DNS"], "subdomain"),
    _make_record("secret.example.com", "example.com", [{"ip": "10.0.0.7"}], ["DNS"], "subdomain"),
    _make_record("jenkins.example.com", "example.com", [{"ip": "10.0.0.8"}], ["DNS"], "subdomain"),
])

_SINGLE_RECORD_OUTPUT = _make_record("dev.example.com", "example.com")

_NO_NAME_RECORD = json.dumps({"domain": "example.com", "addresses": [], "sources": [], "tag": "subdomain"})

_MALFORMED_LINE = "this is not json"

_MULTI_ADDRESS_RECORD = json.dumps({
    "name": "multi.example.com",
    "domain": "example.com",
    "addresses": [
        {"ip": "10.0.0.1", "cidr": "10.0.0.0/24"},
        {"ip": "10.0.0.2", "cidr": "10.0.0.0/24"},
    ],
    "sources": ["DNS", "Cert"],
    "tag": "subdomain",
})

_EMPTY_ADDRESSES_RECORD = json.dumps({
    "name": "orphan.example.com",
    "domain": "example.com",
    "addresses": [],
    "sources": [],
    "tag": "subdomain",
})


# ===========================================================================
# Tests
# ===========================================================================


class TestParseAmassJson:
    """Core parser behaviour."""

    def test_empty_output(self) -> None:
        assert parse_amass_json("") == []

    def test_whitespace_only_output(self) -> None:
        assert parse_amass_json("   \n  \n  ") == []

    def test_single_record(self) -> None:
        findings = parse_amass_json(_SINGLE_RECORD_OUTPUT)
        assert len(findings) == 1
        assert "dev.example.com" in findings[0].title

    def test_full_enum_finds_all_assets(self) -> None:
        findings = parse_amass_json(_FULL_ENUM_OUTPUT)
        assert len(findings) == 8

    def test_malformed_lines_skipped(self) -> None:
        output = f"{_SINGLE_RECORD_OUTPUT}\n{_MALFORMED_LINE}\n"
        findings = parse_amass_json(output)
        assert len(findings) == 1

    def test_no_name_record_skipped(self) -> None:
        findings = parse_amass_json(_NO_NAME_RECORD)
        assert len(findings) == 0

    def test_non_dict_records_skipped(self) -> None:
        output = '"just a string"\n123\n'
        findings = parse_amass_json(output)
        assert len(findings) == 0


class TestSeverityClassification:
    """Severity mapping for different discovered asset names."""

    def test_public_subdomain_is_informational(self) -> None:
        output = _make_record("www.example.com", "example.com")
        findings = parse_amass_json(output)
        assert len(findings) == 1
        assert findings[0].severity is Severity.INFORMATIONAL

    def test_admin_is_low(self) -> None:
        output = _make_record("admin.example.com", "example.com")
        findings = parse_amass_json(output)
        assert len(findings) == 1
        assert findings[0].severity is Severity.LOW

    def test_vpn_is_low(self) -> None:
        output = _make_record("vpn.example.com", "example.com")
        findings = parse_amass_json(output)
        assert findings[0].severity is Severity.LOW

    def test_dev_is_low(self) -> None:
        output = _make_record("dev.example.com", "example.com")
        findings = parse_amass_json(output)
        assert findings[0].severity is Severity.LOW

    def test_api_is_low(self) -> None:
        output = _make_record("api.example.com", "example.com")
        findings = parse_amass_json(output)
        assert findings[0].severity is Severity.LOW

    def test_mail_is_low(self) -> None:
        output = _make_record("mail.example.com", "example.com")
        findings = parse_amass_json(output)
        assert findings[0].severity is Severity.LOW

    def test_jenkins_is_low(self) -> None:
        output = _make_record("jenkins.example.com", "example.com")
        findings = parse_amass_json(output)
        assert findings[0].severity is Severity.LOW

    def test_grafana_is_low(self) -> None:
        output = _make_record("grafana.example.com", "example.com")
        findings = parse_amass_json(output)
        assert findings[0].severity is Severity.LOW

    def test_secret_is_medium(self) -> None:
        output = _make_record("secret.example.com", "example.com")
        findings = parse_amass_json(output)
        assert findings[0].severity is Severity.MEDIUM

    def test_backup_is_medium(self) -> None:
        output = _make_record("backup.example.com", "example.com")
        findings = parse_amass_json(output)
        assert findings[0].severity is Severity.MEDIUM

    def test_database_is_medium(self) -> None:
        output = _make_record("database.example.com", "example.com")
        findings = parse_amass_json(output)
        assert findings[0].severity is Severity.MEDIUM

    def test_prod_admin_is_medium(self) -> None:
        output = _make_record("prod-admin.example.com", "example.com")
        findings = parse_amass_json(output)
        assert findings[0].severity is Severity.MEDIUM


class TestEvidence:
    """Evidence is attached to every finding."""

    def test_all_findings_have_evidence(self) -> None:
        findings = parse_amass_json(_FULL_ENUM_OUTPUT)
        for f in findings:
            assert len(f.evidence) == 1

    def test_evidence_contains_name(self) -> None:
        findings = parse_amass_json(_SINGLE_RECORD_OUTPUT)
        assert "Amass:" in findings[0].evidence[0].summary
        assert "dev.example.com" in findings[0].evidence[0].summary

    def test_multi_address_record(self) -> None:
        findings = parse_amass_json(_MULTI_ADDRESS_RECORD)
        assert len(findings) == 1
        assert "10.0.0.1" in findings[0].description
        assert "10.0.0.2" in findings[0].description

    def test_empty_addresses_record(self) -> None:
        findings = parse_amass_json(_EMPTY_ADDRESSES_RECORD)
        assert len(findings) == 1
        assert "unknown" in findings[0].description
