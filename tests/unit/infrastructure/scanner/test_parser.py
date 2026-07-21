"""Unit tests for the Nuclei JSONL parser (pure, no subprocess)."""

from __future__ import annotations

from kingsec.domain import Severity
from kingsec.infrastructure.scanner import parse_nuclei_jsonl


def _line(**info) -> str:
    import json

    template_id = info.pop("template_id", "tmpl-1")
    matched_at = info.pop("matched_at", "http://10.0.0.5")
    return json.dumps({"template-id": template_id, "info": info, "type": "http", "matched-at": matched_at})


class TestSeverityMapping:
    def test_maps_all_known_severities(self) -> None:
        output = "\n".join(_line(name=f"F{sev}", severity=sev) for sev in ("info", "low", "medium", "high", "critical"))
        findings = parse_nuclei_jsonl(output)
        assert [f.severity for f in findings] == [
            Severity.INFORMATIONAL,
            Severity.LOW,
            Severity.MEDIUM,
            Severity.HIGH,
            Severity.CRITICAL,
        ]

    def test_unknown_severity_defaults_to_informational(self) -> None:
        findings = parse_nuclei_jsonl(_line(name="X", severity="bogus"))
        assert findings[0].severity is Severity.INFORMATIONAL


class TestFieldExtraction:
    def test_title_description_and_evidence(self) -> None:
        findings = parse_nuclei_jsonl(_line(name="SQL Injection", severity="high", description="injectable"))
        finding = findings[0]
        assert finding.title == "SQL Injection"
        assert finding.description == "injectable"
        assert len(finding.evidence) == 1
        assert "10.0.0.5" in finding.evidence[0].detail

    def test_remediation_becomes_recommendation(self) -> None:
        findings = parse_nuclei_jsonl(_line(name="X", severity="medium", remediation="apply the patch"))
        assert len(findings[0].recommendations) == 1
        assert findings[0].recommendations[0].description == "apply the patch"

    def test_missing_name_falls_back_to_template_id(self) -> None:
        findings = parse_nuclei_jsonl(_line(template_id="CVE-2021-9", severity="low"))
        assert findings[0].title == "CVE-2021-9"


class TestResilience:
    def test_empty_output_is_no_findings(self) -> None:
        assert parse_nuclei_jsonl("") == []
        assert parse_nuclei_jsonl("\n  \n") == []

    def test_non_json_lines_are_skipped(self) -> None:
        output = "\n".join(["a stray banner line", _line(name="Real", severity="high"), "another"])
        findings = parse_nuclei_jsonl(output)
        assert len(findings) == 1
        assert findings[0].title == "Real"

    def test_record_without_name_or_template_is_skipped(self) -> None:
        import json

        output = json.dumps({"info": {"severity": "high"}})  # no id, no name
        assert parse_nuclei_jsonl(output) == []
