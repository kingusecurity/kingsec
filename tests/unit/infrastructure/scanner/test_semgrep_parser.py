"""Semgrep parser: comprehensive tests for parse_semgrep_json."""

from __future__ import annotations

import json

import pytest

from kingsec.domain import Severity
from kingsec.infrastructure.scanner.errors import ScannerOutputError
from kingsec.infrastructure.scanner.semgrep_parser import parse_semgrep_json

# ---------------------------------------------------------------------------
# Fixtures: sample Semgrep JSON outputs
# ---------------------------------------------------------------------------

_EMPTY_OUTPUT = ""

_EMPTY_RESULTS = json.dumps({"results": []})

_NO_RESULTS_KEY = json.dumps({})


def _make_result(
    check_id: str = "python.lang.security.audit.dangerous-system-call",
    path: str = "app.py",
    start_line: int = 10,
    end_line: int = 10,
    message: str = "Dangerous system call detected",
    severity: str = "ERROR",
    category: str = "security",
    confidence: str = "HIGH",
    cve: str | list[str] | None = None,
    cwe: str | list[str] | None = None,
    references: list[str] | None = None,
    fix: str | None = None,
) -> dict:
    """Build a single Semgrep result dict."""
    metadata: dict[str, object] = {
        "category": category,
        "confidence": confidence,
    }
    if cve is not None:
        metadata["cve"] = cve
    if cwe is not None:
        metadata["cwe"] = cwe
    if references is not None:
        metadata["references"] = references
    extra: dict[str, object] = {
        "message": message,
        "severity": severity,
        "metadata": metadata,
    }
    if fix is not None:
        extra["fix"] = fix
    return {
        "check_id": check_id,
        "path": path,
        "start": {"line": start_line, "col": 1},
        "end": {"line": end_line, "col": 50},
        "extra": extra,
    }


_RESULT_ERROR = _make_result(
    check_id="python.lang.security.audit.hardcoded-password",
    path="config.py",
    start_line=5,
    end_line=5,
    message="Hardcoded password found",
    severity="ERROR",
    category="security",
    confidence="HIGH",
)

_RESULT_WARNING = _make_result(
    check_id="python.best-practice.use-assert-in",
    path="tests/test_main.py",
    start_line=20,
    end_line=25,
    message="Use assert instead of if for checks",
    severity="WARNING",
    category="best-practice",
    confidence="MEDIUM",
)

_RESULT_INFO = _make_result(
    check_id="python.lang.maintainability.use-logging",
    path="utils.py",
    start_line=15,
    end_line=15,
    message="Use logging instead of print",
    severity="INFO",
    category="maintainability",
    confidence="LOW",
)

_FULL_OUTPUT = json.dumps(
    {
        "results": [_RESULT_ERROR, _RESULT_WARNING, _RESULT_INFO],
    }
)

_SINGLE_RESULT_OUTPUT = json.dumps(
    {
        "results": [_RESULT_ERROR],
    }
)

_MALFORMED_JSON = "this is not json"


# ===========================================================================
# Tests
# ===========================================================================


class TestParseSemgrepJson:
    """Core parser behaviour."""

    def test_empty_output_is_not_a_valid_semgrep_report(self) -> None:
        with pytest.raises(ScannerOutputError):
            parse_semgrep_json(_EMPTY_OUTPUT)

    def test_malformed_json_raises_output_error(self) -> None:
        with pytest.raises(ScannerOutputError):
            parse_semgrep_json(_MALFORMED_JSON)

    def test_empty_results(self) -> None:
        assert parse_semgrep_json(_EMPTY_RESULTS) == []

    def test_no_results_key_raises_output_error(self) -> None:
        with pytest.raises(ScannerOutputError):
            parse_semgrep_json(_NO_RESULTS_KEY)

    def test_non_object_report_raises_output_error(self) -> None:
        with pytest.raises(ScannerOutputError):
            parse_semgrep_json(json.dumps([]))

    def test_non_array_results_raises_output_error(self) -> None:
        with pytest.raises(ScannerOutputError):
            parse_semgrep_json(json.dumps({"results": {}}))

    def test_single_result(self) -> None:
        findings = parse_semgrep_json(_SINGLE_RESULT_OUTPUT)
        assert len(findings) == 1
        assert "hardcoded-password" in findings[0].title

    def test_multiple_results(self) -> None:
        findings = parse_semgrep_json(_FULL_OUTPUT)
        assert len(findings) == 3

    def test_non_dict_results_raise_output_error(self) -> None:
        output = json.dumps({"results": ["not a dict", 123]})
        with pytest.raises(ScannerOutputError):
            parse_semgrep_json(output)

    def test_incomplete_result_raises_output_error(self) -> None:
        with pytest.raises(ScannerOutputError):
            parse_semgrep_json(json.dumps({"results": [{}]}))

    def test_empty_results_array(self) -> None:
        output = json.dumps({"results": []})
        assert parse_semgrep_json(output) == []


class TestSeverityClassification:
    """Severity mapping for different Semgrep severity levels."""

    def test_error_maps_to_high(self) -> None:
        output = json.dumps({"results": [_RESULT_ERROR]})
        findings = parse_semgrep_json(output)
        assert findings[0].severity is Severity.HIGH

    def test_warning_maps_to_medium(self) -> None:
        output = json.dumps({"results": [_RESULT_WARNING]})
        findings = parse_semgrep_json(output)
        assert findings[0].severity is Severity.MEDIUM

    def test_info_maps_to_low(self) -> None:
        output = json.dumps({"results": [_RESULT_INFO]})
        findings = parse_semgrep_json(output)
        assert findings[0].severity is Severity.LOW

    def test_unknown_severity_maps_to_low(self) -> None:
        result = _make_result(severity="UNKNOWN")
        output = json.dumps({"results": [result]})
        findings = parse_semgrep_json(output)
        assert findings[0].severity is Severity.LOW


class TestEvidence:
    """Evidence is attached to every finding."""

    def test_all_findings_have_evidence(self) -> None:
        findings = parse_semgrep_json(_FULL_OUTPUT)
        for f in findings:
            assert len(f.evidence) == 1

    def test_evidence_contains_rule_id(self) -> None:
        findings = parse_semgrep_json(_SINGLE_RESULT_OUTPUT)
        assert "Semgrep:" in findings[0].evidence[0].summary
        assert "hardcoded-password" in findings[0].evidence[0].summary

    def test_description_contains_file_path(self) -> None:
        findings = parse_semgrep_json(_SINGLE_RESULT_OUTPUT)
        assert "config.py" in findings[0].description

    def test_description_contains_line_numbers(self) -> None:
        findings = parse_semgrep_json(_SINGLE_RESULT_OUTPUT)
        assert "5-5" in findings[0].description

    def test_description_contains_severity(self) -> None:
        findings = parse_semgrep_json(_SINGLE_RESULT_OUTPUT)
        assert "ERROR" in findings[0].description

    def test_description_contains_message(self) -> None:
        findings = parse_semgrep_json(_SINGLE_RESULT_OUTPUT)
        assert "Hardcoded password found" in findings[0].description


class TestCveCweReferences:
    """CVE, CWE, references, and fix extraction from metadata."""

    def test_cve_in_description(self) -> None:
        result = _make_result(cve="CVE-2021-12345")
        findings = parse_semgrep_json(json.dumps({"results": [result]}))
        assert "CVE-2021-12345" in findings[0].description
        assert "cve: CVE-2021-12345" in findings[0].evidence[0].detail

    def test_cve_list_in_description(self) -> None:
        result = _make_result(cve=["CVE-2021-1", "CVE-2021-2"])
        findings = parse_semgrep_json(json.dumps({"results": [result]}))
        assert "CVE-2021-1" in findings[0].description
        assert "CVE-2021-2" in findings[0].description

    def test_cwe_in_evidence(self) -> None:
        result = _make_result(cwe="CWE-79")
        findings = parse_semgrep_json(json.dumps({"results": [result]}))
        assert "CWE-79" in findings[0].description
        assert "cwe: CWE-79" in findings[0].evidence[0].detail

    def test_references_in_evidence(self) -> None:
        result = _make_result(references=["https://example.com/1"])
        findings = parse_semgrep_json(json.dumps({"results": [result]}))
        assert "https://example.com/1" in findings[0].evidence[0].detail

    def test_fix_becomes_recommendation(self) -> None:
        result = _make_result(fix="use `secrets` module instead")
        findings = parse_semgrep_json(json.dumps({"results": [result]}))
        assert len(findings[0].recommendations) == 1
        assert findings[0].recommendations[0].description == "use `secrets` module instead"

    def test_no_fix_no_recommendation(self) -> None:
        findings = parse_semgrep_json(_SINGLE_RESULT_OUTPUT)
        assert len(findings[0].recommendations) == 0
