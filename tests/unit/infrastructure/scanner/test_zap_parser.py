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


def _make_real_format_alert(
    alert: str = "PII Disclosure",
    riskcode: str = "3",
    confidence: str = "3",
    desc: str = "<p>Potential PII was found in the response.</p>",
    solution: str = "<p>Check the response for PII.</p>",
    instances: list[dict] | None = None,
) -> dict:
    """Build an alert in ZAP's REAL Traditional JSON report shape.

    The real format uses ``desc`` (not ``description``) and nests
    per-occurrence detail under ``instances`` - there is no top-level
    ``url``/``param``. See
    https://www.zaproxy.org/docs/desktop/addons/report-generation/report-traditional-json/
    """
    return {
        "pluginid": "10001",
        "alert": alert,
        "name": alert,
        "riskcode": riskcode,
        "confidence": confidence,
        "riskdesc": "High (High)",
        "desc": desc,
        "instances": (
            instances
            if instances is not None
            else [
                {
                    "uri": "https://example.com/contact",
                    "method": "GET",
                    "param": "",
                    "attack": "",
                    "evidence": "john@example.com",
                    "otherinfo": "",
                }
            ]
        ),
        "count": "1",
        "solution": solution,
        "reference": "",
    }


_REAL_FORMAT_OUTPUT = json.dumps(
    {"site": [{"@name": "https://example.com", "@host": "example.com", "alerts": [_make_real_format_alert()]}]}
)


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


class TestRealZapFormat:
    """ZAP's real Traditional JSON report shape (desc + instances).

    Regression: the parser used to read only the normalized ``description``
    / top-level ``url`` / ``param`` keys, which the real format never
    emits - so EVERY ZAP finding shipped with an empty description and no
    per-instance detail (proven live, 2026-10-14: all 13 ZAP findings in a
    production report carried empty descriptions, including the High
    "PII Disclosure" finding).
    """

    def test_desc_is_parsed(self) -> None:
        findings = parse_zap_json(_REAL_FORMAT_OUTPUT)
        assert len(findings) == 1
        assert "Potential PII was found in the response." in findings[0].description

    def test_instance_uri_becomes_location(self) -> None:
        findings = parse_zap_json(_REAL_FORMAT_OUTPUT)
        assert findings[0].title == "PII Disclosure — https://example.com/contact"
        assert "https://example.com/contact" in findings[0].description

    def test_instance_evidence_is_kept(self) -> None:
        findings = parse_zap_json(_REAL_FORMAT_OUTPUT)
        assert "john@example.com" in findings[0].evidence[0].detail

    def test_instance_param_is_kept(self) -> None:
        alert = _make_real_format_alert(
            instances=[{"uri": "https://example.com/search", "param": "q", "evidence": "<script>"}]
        )
        findings = parse_zap_json(json.dumps({"site": [{"@name": "https://example.com", "alerts": [alert]}]}))
        assert "q" in findings[0].description
        assert "param: q" in findings[0].description

    def test_multiple_instances_are_counted(self) -> None:
        alert = _make_real_format_alert(
            instances=[
                {"uri": "https://example.com/a", "param": "", "evidence": ""},
                {"uri": "https://example.com/b", "param": "", "evidence": ""},
            ]
        )
        findings = parse_zap_json(json.dumps({"site": [{"@name": "https://example.com", "alerts": [alert]}]}))
        assert len(findings) == 1
        assert "instances: 2" in findings[0].evidence[0].detail

    def test_no_instances_falls_back_to_site(self) -> None:
        alert = _make_real_format_alert(instances=[])
        findings = parse_zap_json(json.dumps({"site": [{"@name": "https://example.com", "alerts": [alert]}]}))
        assert findings[0].title == "PII Disclosure — https://example.com"

    def test_legacy_top_level_keys_still_work(self) -> None:
        # The normalized fixture shape (description/url/param at top level)
        # keeps working as a fallback.
        findings = parse_zap_json(_SINGLE_ALERT_OUTPUT)
        assert "SQL injection found in login form" in findings[0].description
        assert "username" in findings[0].description


class TestRecommendations:
    """Solution → Recommendation mapping for ZAP alerts."""

    def test_solution_becomes_recommendation(self) -> None:
        findings = parse_zap_json(_SINGLE_ALERT_OUTPUT)
        assert len(findings[0].recommendations) == 1
        assert findings[0].recommendations[0].description == "Use parameterized queries"

    def test_solution_missing_no_recommendation(self) -> None:
        alert = _make_alert(solution="", reference="", riskcode="0")
        output = json.dumps({"site": [_make_site(alerts=[alert])]})
        findings = parse_zap_json(output)
        assert len(findings[0].recommendations) == 0

    def test_reference_in_evidence(self) -> None:
        findings = parse_zap_json(_SINGLE_ALERT_OUTPUT)
        assert "https://owasp.org/sql-injection" in findings[0].evidence[0].detail

    def test_reference_empty_not_in_evidence(self) -> None:
        output = json.dumps({"site": [_make_site(alerts=[_ALERT_LOW])]})
        findings = parse_zap_json(output)
        assert "reference:" not in findings[0].evidence[0].detail
