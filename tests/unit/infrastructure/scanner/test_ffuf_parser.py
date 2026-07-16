"""ffuf parser: comprehensive tests for parse_ffuf_json."""

from __future__ import annotations

import pytest

from kingsec.domain import Severity
from kingsec.infrastructure.scanner.ffuf_parser import parse_ffuf_json


# ---------------------------------------------------------------------------
# Fixtures: sample ffuf JSONL outputs
# ---------------------------------------------------------------------------

_EMPTY_OUTPUT = ""

_SAMPLE_LINE = (
    '{"input":{"FUZZ":"admin"},"position":1,"status":200,"length":1234,'
    '"words":56,"lines":23,"content-type":"text/html","redirectlocation":"",'
    '"url":"http://example.com/admin","duration":123456,"resultfile":"",'
    '"host":"example.com"}'
)

_MULTI_LINE = (
    '{"input":{"FUZZ":"admin"},"position":1,"status":200,"length":1234,'
    '"words":56,"lines":23,"content-type":"text/html","redirectlocation":"",'
    '"url":"http://example.com/admin","duration":123456,"resultfile":"",'
    '"host":"example.com"}\n'
    '{"input":{"FUZZ":"backup"},"position":2,"status":403,"length":567,'
    '"words":12,"lines":5,"content-type":"text/html","redirectlocation":"",'
    '"url":"http://example.com/backup","duration":98765,"resultfile":"",'
    '"host":"example.com"}\n'
    '{"input":{"FUZZ":".git"},"position":3,"status":200,"length":890,'
    '"words":34,"lines":12,"content-type":"text/html","redirectlocation":"",'
    '"url":"http://example.com/.git","duration":45678,"resultfile":"",'
    '"host":"example.com"}\n'
)

_SUMMARY_LINE = (
    '{"results":[{"input":{"FUZZ":"admin"},"position":1,"status":200,'
    '"length":1234,"words":56,"lines":23,"content-type":"text/html",'
    '"redirectlocation":"","url":"http://example.com/admin",'
    '"duration":123456,"resultfile":"","host":"example.com"}]}'
)


# ===========================================================================
# Tests
# ===========================================================================


class TestParseFfufJson:
    """Core parser behaviour."""

    def test_empty_output(self) -> None:
        assert parse_ffuf_json("") == []

    def test_whitespace_only_output(self) -> None:
        assert parse_ffuf_json("   \n  \n  ") == []

    def test_single_line(self) -> None:
        findings = parse_ffuf_json(_SAMPLE_LINE)
        assert len(findings) == 1

    def test_multi_line(self) -> None:
        findings = parse_ffuf_json(_MULTI_LINE)
        assert len(findings) == 3

    def test_summary_line_ignored(self) -> None:
        findings = parse_ffuf_json(_SUMMARY_LINE)
        assert len(findings) == 0

    def test_malformed_json_skipped(self) -> None:
        output = "not json\n" + _SAMPLE_LINE
        findings = parse_ffuf_json(output)
        assert len(findings) == 1

    def test_non_dict_json_skipped(self) -> None:
        output = '"just a string"\n42\n' + _SAMPLE_LINE
        findings = parse_ffuf_json(output)
        assert len(findings) == 1


class TestSeverityClassification:
    """Severity mapping for different HTTP status codes and paths."""

    def test_status_200_is_low(self) -> None:
        line = (
            '{"input":{"FUZZ":"test"},"status":200,"length":100,"words":10,'
            '"lines":5,"content-type":"text/html","redirectlocation":"",'
            '"url":"http://example.com/test","duration":1000,'
            '"resultfile":"","host":"example.com"}'
        )
        findings = parse_ffuf_json(line)
        assert findings[0].severity is Severity.LOW

    def test_status_201_is_low(self) -> None:
        line = (
            '{"input":{"FUZZ":"test"},"status":201,"length":100,"words":10,'
            '"lines":5,"content-type":"text/html","redirectlocation":"",'
            '"url":"http://example.com/test","duration":1000,'
            '"resultfile":"","host":"example.com"}'
        )
        findings = parse_ffuf_json(line)
        assert findings[0].severity is Severity.LOW

    def test_status_204_is_informational(self) -> None:
        line = (
            '{"input":{"FUZZ":"test"},"status":204,"length":0,"words":0,'
            '"lines":0,"content-type":"","redirectlocation":"",'
            '"url":"http://example.com/test","duration":1000,'
            '"resultfile":"","host":"example.com"}'
        )
        findings = parse_ffuf_json(line)
        assert findings[0].severity is Severity.INFORMATIONAL

    def test_status_301_is_informational(self) -> None:
        line = (
            '{"input":{"FUZZ":"test"},"status":301,"length":0,"words":0,'
            '"lines":0,"content-type":"","redirectlocation":"/new",'
            '"url":"http://example.com/test","duration":1000,'
            '"resultfile":"","host":"example.com"}'
        )
        findings = parse_ffuf_json(line)
        assert findings[0].severity is Severity.INFORMATIONAL

    def test_status_302_is_informational(self) -> None:
        line = (
            '{"input":{"FUZZ":"test"},"status":302,"length":0,"words":0,'
            '"lines":0,"content-type":"","redirectlocation":"/login",'
            '"url":"http://example.com/test","duration":1000,'
            '"resultfile":"","host":"example.com"}'
        )
        findings = parse_ffuf_json(line)
        assert findings[0].severity is Severity.INFORMATIONAL

    def test_status_401_is_medium(self) -> None:
        line = (
            '{"input":{"FUZZ":"test"},"status":401,"length":200,"words":20,'
            '"lines":8,"content-type":"text/html","redirectlocation":"",'
            '"url":"http://example.com/test","duration":1000,'
            '"resultfile":"","host":"example.com"}'
        )
        findings = parse_ffuf_json(line)
        assert findings[0].severity is Severity.MEDIUM

    def test_status_403_is_medium(self) -> None:
        line = (
            '{"input":{"FUZZ":"test"},"status":403,"length":200,"words":20,'
            '"lines":8,"content-type":"text/html","redirectlocation":"",'
            '"url":"http://example.com/test","duration":1000,'
            '"resultfile":"","host":"example.com"}'
        )
        findings = parse_ffuf_json(line)
        assert findings[0].severity is Severity.MEDIUM

    def test_status_500_is_high(self) -> None:
        line = (
            '{"input":{"FUZZ":"test"},"status":500,"length":500,"words":40,'
            '"lines":15,"content-type":"text/html","redirectlocation":"",'
            '"url":"http://example.com/test","duration":1000,'
            '"resultfile":"","host":"example.com"}'
        )
        findings = parse_ffuf_json(line)
        assert findings[0].severity is Severity.HIGH

    def test_status_503_is_high(self) -> None:
        line = (
            '{"input":{"FUZZ":"test"},"status":503,"length":300,"words":25,'
            '"lines":10,"content-type":"text/html","redirectlocation":"",'
            '"url":"http://example.com/test","duration":1000,'
            '"resultfile":"","host":"example.com"}'
        )
        findings = parse_ffuf_json(line)
        assert findings[0].severity is Severity.HIGH

    def test_sensitive_extension_is_high(self) -> None:
        line = (
            '{"input":{"FUZZ":".env"},"status":200,"length":500,"words":30,'
            '"lines":10,"content-type":"text/html","redirectlocation":"",'
            '"url":"http://example.com/.env","duration":1000,'
            '"resultfile":"","host":"example.com"}'
        )
        findings = parse_ffuf_json(line)
        assert findings[0].severity is Severity.HIGH

    def test_git_extension_is_high(self) -> None:
        line = (
            '{"input":{"FUZZ":".git"},"status":200,"length":890,"words":34,'
            '"lines":12,"content-type":"text/html","redirectlocation":"",'
            '"url":"http://example.com/.git","duration":1000,'
            '"resultfile":"","host":"example.com"}'
        )
        findings = parse_ffuf_json(line)
        assert findings[0].severity is Severity.HIGH

    def test_admin_path_is_medium(self) -> None:
        line = (
            '{"input":{"FUZZ":"admin"},"status":200,"length":1234,"words":56,'
            '"lines":23,"content-type":"text/html","redirectlocation":"",'
            '"url":"http://example.com/admin","duration":1000,'
            '"resultfile":"","host":"example.com"}'
        )
        findings = parse_ffuf_json(line)
        assert findings[0].severity is Severity.MEDIUM

    def test_login_path_is_medium(self) -> None:
        line = (
            '{"input":{"FUZZ":"login"},"status":200,"length":800,"words":40,'
            '"lines":15,"content-type":"text/html","redirectlocation":"",'
            '"url":"http://example.com/login","duration":1000,'
            '"resultfile":"","host":"example.com"}'
        )
        findings = parse_ffuf_json(line)
        assert findings[0].severity is Severity.MEDIUM


class TestEvidence:
    """Evidence is attached to every finding."""

    def test_all_findings_have_evidence(self) -> None:
        findings = parse_ffuf_json(_MULTI_LINE)
        for f in findings:
            assert len(f.evidence) == 1

    def test_evidence_contains_status(self) -> None:
        findings = parse_ffuf_json(_SAMPLE_LINE)
        assert "200" in findings[0].evidence[0].summary

    def test_evidence_contains_url(self) -> None:
        findings = parse_ffuf_json(_SAMPLE_LINE)
        assert "example.com" in findings[0].evidence[0].detail


class TestFindingContent:
    """Finding title and description contain expected data."""

    def test_title_contains_status(self) -> None:
        findings = parse_ffuf_json(_SAMPLE_LINE)
        assert "200" in findings[0].title

    def test_title_contains_url(self) -> None:
        findings = parse_ffuf_json(_SAMPLE_LINE)
        assert "example.com" in findings[0].title

    def test_description_contains_fuzz_value(self) -> None:
        findings = parse_ffuf_json(_SAMPLE_LINE)
        assert "admin" in findings[0].description
