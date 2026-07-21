"""ZAP parser: comprehensive tests for parse_zap_json."""

from __future__ import annotations

import json

from kingsec.domain import Severity
from kingsec.infrastructure.scanner.zap_parser import parse_zap_json

# ---------------------------------------------------------------------------
# Fixtures: sample ZAP JSON outputs
# ---------------------------------------------------------------------------

_EMPTY_OUTPUT = ""

_EMPTY_RESULTS = json.dumps({"site": []})

_NO_SITE_KEY = json.dumps({})


def _make_alert(
    alert: str = "X-Content-Type-Options Header Missing",
    riskcode: str = "1",
    confidence: str = "Medium",
    description: str = "The header is missing",
    solution: str = "Add the header",
    reference: str = "https://example.com",
    url: str = "http://example.com/",
    param: str = "",
) -> dict:
    """Build a single ZAP alert dict."""
    return {
        "alert": alert,
        "riskcode": riskcode,
        "confidence": confidence,
        "description": description,
        "solution": solution,
        "reference": reference,
        "url": url,
        "param": param,
    }


def _make_site(
    name: str = "http://example.com",
    host: str = "example.com",
    alerts: list[dict] | None = None,
) -> dict:
    """Build a ZAP site dict."""
    return {
        "@name": name,
        "host": host,
        "alerts": alerts or [],
    }


_ALERT_HIGH = _make_alert(
    alert="SQL Injection",
    riskcode="3",
    confidence="High",
    description="SQL injection found in login form",
    solution="Use parameterized queries",
    reference="https://owasp.org/sql-injection",
    url="http://example.com/login",
    param="username",
)

_ALERT_MEDIUM = _make_alert(
    alert="Cross-Site Scripting (Reflected)",
    riskcode="2",
    confidence="Medium",
    description="XSS found in search parameter",
    solution="Encode output",
    reference="https://owasp.org/xss",
    url="http://example.com/search",
    param="q",
)

_ALERT_LOW = _make_alert(
    alert="X-Content-Type-Options Header Missing",
    riskcode="1",
    confidence="Medium",
    description="Header missing",
    solution="Add header",
    reference="",
    url="http://example.com/",
    param="",
)

_ALERT_INFO = _make_alert(
    alert="Information Disclosure - Debug Messages",
    riskcode="0",
    confidence="Low",
    description="Debug messages found",
    solution="Remove debug messages",
    reference="",
    url="http://example.com/debug",
    param="",
)

_FULL_OUTPUT = json.dumps(
    {
        "site": [
            _make_site("http://example.com", "example.com", [_ALERT_HIGH, _ALERT_LOW]),
            _make_site("http://example.com/api", "example.com", [_ALERT_MEDIUM]),
        ]
    }
)

_SINGLE_ALERT_OUTPUT = json.dumps({"site": [_make_site("http://example.com", "example.com", [_ALERT_HIGH])]})

_MALFORMED_JSON = "this is not json"


# ===========================================================================
# Tests
# ===========================================================================


class TestParseZapJson:
    """Core parser behaviour."""

    def test_empty_output(self) -> None:
        assert parse_zap_json("") == []

    def test_malformed_json(self) -> None:
        assert parse_zap_json(_MALFORMED_JSON) == []

    def test_empty_results(self) -> None:
        assert parse_zap_json(_EMPTY_RESULTS) == []

    def test_no_site_key(self) -> None:
        assert parse_zap_json(_NO_SITE_KEY) == []

    def test_single_alert(self) -> None:
        findings = parse_zap_json(_SINGLE_ALERT_OUTPUT)
        assert len(findings) == 1
        assert "SQL Injection" in findings[0].title

    def test_multiple_alerts(self) -> None:
        findings = parse_zap_json(_FULL_OUTPUT)
        assert len(findings) == 3

    def test_non_dict_results_skipped(self) -> None:
        output = json.dumps({"site": ["not a dict", 123]})
        findings = parse_zap_json(output)
        assert len(findings) == 0

    def test_empty_alerts(self) -> None:
        output = json.dumps({"site": [_make_site("http://example.com", "example.com", [])]})
        assert parse_zap_json(output) == []


class TestSeverityClassification:
    """Severity mapping for different ZAP risk codes."""

    def test_high_risk_maps_to_high(self) -> None:
        output = json.dumps({"site": [_make_site("http://example.com", "example.com", [_ALERT_HIGH])]})
        findings = parse_zap_json(output)
        assert findings[0].severity is Severity.HIGH

    def test_medium_risk_maps_to_medium(self) -> None:
        output = json.dumps({"site": [_make_site("http://example.com", "example.com", [_ALERT_MEDIUM])]})
        findings = parse_zap_json(output)
        assert findings[0].severity is Severity.MEDIUM

    def test_low_risk_maps_to_low(self) -> None:
        output = json.dumps({"site": [_make_site("http://example.com", "example.com", [_ALERT_LOW])]})
        findings = parse_zap_json(output)
        assert findings[0].severity is Severity.LOW

    def test_info_risk_maps_to_informational(self) -> None:
        output = json.dumps({"site": [_make_site("http://example.com", "example.com", [_ALERT_INFO])]})
        findings = parse_zap_json(output)
        assert findings[0].severity is Severity.INFORMATIONAL

    def test_string_risk_high(self) -> None:
        alert = _make_alert(riskcode="High")
        output = json.dumps({"site": [_make_site(alerts=[alert])]})
        findings = parse_zap_json(output)
        assert findings[0].severity is Severity.HIGH

    def test_string_risk_medium(self) -> None:
        alert = _make_alert(riskcode="Medium")
        output = json.dumps({"site": [_make_site(alerts=[alert])]})
        findings = parse_zap_json(output)
        assert findings[0].severity is Severity.MEDIUM


class TestEvidence:
    """Evidence is attached to every finding."""

    def test_all_findings_have_evidence(self) -> None:
        findings = parse_zap_json(_FULL_OUTPUT)
        for f in findings:
            assert len(f.evidence) == 1

    def test_evidence_contains_alert_name(self) -> None:
        findings = parse_zap_json(_SINGLE_ALERT_OUTPUT)
        assert "ZAP:" in findings[0].evidence[0].summary
        assert "SQL Injection" in findings[0].evidence[0].summary

    def test_description_contains_param(self) -> None:
        findings = parse_zap_json(_SINGLE_ALERT_OUTPUT)
        assert "username" in findings[0].description

    def test_description_no_param(self) -> None:
        output = json.dumps({"site": [_make_site(alerts=[_ALERT_LOW])]})
        findings = parse_zap_json(output)
        assert "param:" not in findings[0].description
