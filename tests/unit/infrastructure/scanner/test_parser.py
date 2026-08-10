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


class TestCveCweReferences:
    """CVE, CWE, and references extraction from Nuclei classification."""

    def test_cve_in_description(self) -> None:
        import json

        record = {
            "template-id": "cve-test",
            "matched-at": "http://10.0.0.5/test",
            "info": {
                "name": "Test CVE",
                "severity": "high",
                "classification": {"cve-id": ["CVE-2021-12345", "CVE-2021-67890"]},
            },
        }
        findings = parse_nuclei_jsonl(json.dumps(record))
        assert "CVE-2021-12345" in findings[0].description
        assert "CVE-2021-67890" in findings[0].description
        assert "cve: CVE-2021-12345, CVE-2021-67890" in findings[0].evidence[0].detail
        # Structured field, not just flattened text - this is the actual fix:
        # the data now reaches a queryable field, not only free text.
        assert findings[0].cve_ids == ("CVE-2021-12345", "CVE-2021-67890")

    def test_cvss_score_and_vector_extracted(self) -> None:
        """Nuclei's classification block also carries cvss-score/cvss-metrics
        for CVE-tagged templates - previously not read at all."""
        import json

        record = {
            "template-id": "cvss-test",
            "matched-at": "http://10.0.0.5/test",
            "info": {
                "name": "Test CVSS",
                "severity": "high",
                "classification": {
                    "cve-id": ["CVE-2021-99999"],
                    "cvss-score": 7.5,
                    "cvss-metrics": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H",
                },
            },
        }
        findings = parse_nuclei_jsonl(json.dumps(record))
        assert findings[0].cvss_score == 7.5
        assert findings[0].cvss_vector == "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H"

    def test_out_of_range_cvss_score_is_dropped_not_raised(self) -> None:
        """A malformed classification block (bad score) must degrade to no
        score, not crash the whole scan's parse over one odd template."""
        import json

        record = {
            "template-id": "bad-cvss",
            "matched-at": "http://10.0.0.5/test",
            "info": {
                "name": "Bad CVSS",
                "severity": "low",
                "classification": {"cvss-score": 42.0},
            },
        }
        findings = parse_nuclei_jsonl(json.dumps(record))
        assert findings[0].cvss_score is None

    def test_cwe_in_description(self) -> None:
        import json

        record = {
            "template-id": "cwe-test",
            "matched-at": "http://10.0.0.5/test",
            "info": {
                "name": "Test CWE",
                "severity": "medium",
                "classification": {"cwe-id": ["CWE-79", "CWE-89"]},
            },
        }
        findings = parse_nuclei_jsonl(json.dumps(record))
        assert "CWE-79" in findings[0].description
        assert "CWE-89" in findings[0].description
        assert "cwe: CWE-79, CWE-89" in findings[0].evidence[0].detail
        assert findings[0].cwe_ids == ("CWE-79", "CWE-89")

    def test_references_in_evidence(self) -> None:
        import json

        record = {
            "template-id": "ref-test",
            "matched-at": "http://10.0.0.5/test",
            "info": {
                "name": "Test Refs",
                "severity": "low",
                "references": ["https://example.com/1", "https://example.com/2"],
            },
        }
        findings = parse_nuclei_jsonl(json.dumps(record))
        assert "https://example.com/1" in findings[0].evidence[0].detail
        assert "https://example.com/2" in findings[0].evidence[0].detail

    def test_cve_as_string_not_list(self) -> None:
        import json

        record = {
            "template-id": "cve-str",
            "matched-at": "http://10.0.0.5/test",
            "info": {
                "name": "CVE String",
                "severity": "critical",
                "classification": {"cve-id": "CVE-2021-1"},
            },
        }
        findings = parse_nuclei_jsonl(json.dumps(record))
        assert "CVE-2021-1" in findings[0].description

    def test_no_classification_no_error(self) -> None:
        findings = parse_nuclei_jsonl(_line(name="No Class", severity="info"))
        assert findings[0].title == "No Class"
        assert "CVE:" not in findings[0].description
        assert "CWE:" not in findings[0].description


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
