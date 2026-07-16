"""Semgrep parser: comprehensive tests for parse_semgrep_json."""

from __future__ import annotations

import json

import pytest

from kingsec.domain import Severity
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
) -> dict:
    """Build a single Semgrep result dict."""
    return {
        "check_id": check_id,
        "path": path,
        "start": {"line": start_line, "col": 1},
        "end": {"line": end_line, "col": 50},
        "extra": {
            "message": message,
            "severity": severity,
            "metadata": {
                "category": category,
                "confidence": confidence,
            },
        },
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

_FULL_OUTPUT = json.dumps({
    "results": [_RESULT_ERROR, _RESULT_WARNING, _RESULT_INFO],
})

_SINGLE_RESULT_OUTPUT = json.dumps({
    "results": [_RESULT_ERROR],
})

_MALFORMED_JSON = "this is not json"


# ===========================================================================
# Tests
# ===========================================================================


class TestParseSemgrepJson:
    """Core parser behaviour."""

    def test_empty_output(self) -> None:
        assert parse_semgrep_json("") == []

    def test_malformed_json(self) -> None:
        assert parse_semgrep_json(_MALFORMED_JSON) == []

    def test_empty_results(self) -> None:
        assert parse_semgrep_json(_EMPTY_RESULTS) == []

    def test_no_results_key(self) -> None:
        assert parse_semgrep_json(_NO_RESULTS_KEY) == []

    def test_single_result(self) -> None:
        findings = parse_semgrep_json(_SINGLE_RESULT_OUTPUT)
        assert len(findings) == 1
        assert "hardcoded-password" in findings[0].title

    def test_multiple_results(self) -> None:
        findings = parse_semgrep_json(_FULL_OUTPUT)
        assert len(findings) == 3

    def test_non_dict_results_skipped(self) -> None:
        output = json.dumps({"results": ["not a dict", 123]})
        findings = parse_semgrep_json(output)
        assert len(findings) == 0

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
