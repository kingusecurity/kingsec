"""Unit tests for the Nuclei JSONL parser (pure, no subprocess)."""

from __future__ import annotations

from kingsec.domain import Severity
from kingsec.infrastructure.scanner import parse_nuclei_jsonl


def _line(**info) -> str:
    import json

    template_id = info.pop("template_id", "tmpl-1")
    matched_at = info.pop("matched_at", "http://10.0.0.5")
    matcher_name = info.pop("matcher_name", None)
    record: dict = {"template-id": template_id, "info": info, "type": "http", "matched-at": matched_at}
    if matcher_name is not None:
        record["matcher-name"] = matcher_name
    return json.dumps(record)


class TestSeverityMapping:
    def test_maps_all_known_severities(self) -> None:
        # Distinct matched_at per line: parse_nuclei_jsonl groups records by
        # (template-id, matched-at), so identical locators would collapse
        # these 5 intentionally-distinct records into one finding.
        output = "\n".join(
            _line(name=f"F{sev}", severity=sev, matched_at=f"http://10.0.0.5/{sev}")
            for sev in ("info", "low", "medium", "high", "critical")
        )
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


class TestMultiMatcherGrouping:
    """Phase 2C Step 2 GAP fix 5: a multi-matcher 'or' template (confirmed
    against the real cached http-missing-security-headers.yaml template -
    matchers-condition: or, 12 independently-named matchers) emits one
    JSONL record per matched matcher against the same (template-id,
    matched-at) - these must collapse into ONE finding, not N duplicates."""

    def test_same_template_and_locator_collapses_to_one_finding(self) -> None:
        output = "\n".join(
            _line(
                template_id="http-missing-security-headers",
                matched_at="http://10.0.0.5/login.php",
                matcher_name=name,
                name="HTTP Missing Security Headers",
                severity="info",
                description="This template searches for missing HTTP security headers.",
            )
            for name in (
                "strict-transport-security",
                "content-security-policy",
                "x-frame-options",
                "x-content-type-options",
                "referrer-policy",
                "permissions-policy",
                "cross-origin-opener-policy",
                "cross-origin-resource-policy",
                "missing-content-type",
                "x-permitted-cross-domain-policies",
            )
        )
        findings = parse_nuclei_jsonl(output)
        assert len(findings) == 1
        assert findings[0].title == "HTTP Missing Security Headers"

    def test_collapsed_finding_lists_the_matched_checks_in_its_description(self) -> None:
        output = "\n".join(
            _line(
                template_id="http-missing-security-headers",
                matched_at="http://10.0.0.5/login.php",
                matcher_name=name,
                name="HTTP Missing Security Headers",
                severity="info",
            )
            for name in ("x-frame-options", "content-security-policy")
        )
        finding = parse_nuclei_jsonl(output)[0]
        assert "x-frame-options" in finding.description
        assert "content-security-policy" in finding.description

    def test_collapsed_finding_keeps_one_evidence_entry_per_matcher(self) -> None:
        output = "\n".join(
            _line(
                template_id="http-missing-security-headers",
                matched_at="http://10.0.0.5/login.php",
                matcher_name=name,
                name="HTTP Missing Security Headers",
                severity="info",
            )
            for name in ("x-frame-options", "content-security-policy", "referrer-policy")
        )
        finding = parse_nuclei_jsonl(output)[0]
        assert len(finding.evidence) == 3
        matcher_mentions = [e for e in finding.evidence if "matcher: x-frame-options" in e.detail]
        assert len(matcher_mentions) == 1

    def test_different_matched_at_does_not_collapse(self) -> None:
        """The same template hitting two different URLs must stay two
        findings - grouping is scoped to (template-id, matched-at), not
        template-id alone."""
        output = "\n".join(
            _line(
                template_id="http-missing-security-headers",
                matched_at=url,
                matcher_name="x-frame-options",
                name="HTTP Missing Security Headers",
                severity="info",
            )
            for url in ("http://10.0.0.5/login.php", "http://10.0.0.5/admin.php")
        )
        findings = parse_nuclei_jsonl(output)
        assert len(findings) == 2

    def test_single_matcher_template_is_unaffected(self) -> None:
        """The overwhelming majority of templates (no matcher-name field at
        all) must render exactly as before this fix: one finding, one
        evidence entry, no 'Matched checks' text in the description."""
        finding = parse_nuclei_jsonl(_line(name="SQL Injection", severity="high", description="injectable"))[0]
        assert len(finding.evidence) == 1
        assert "Matched checks" not in finding.description
        assert "matcher:" not in finding.evidence[0].detail

    def test_ten_header_matchers_collapse_like_the_real_dvwa_evidence(self) -> None:
        """The exact real-data regression this fix closes: 10 of the real
        DVWA report's 28 Informational findings were this one template
        repeated 10 times (docs/audits, Phase 2C Step 2 GAP report) -
        after this fix, they must count as ONE finding."""
        headers = (
            "strict-transport-security",
            "content-security-policy",
            "permissions-policy",
            "x-frame-options",
            "x-content-type-options",
            "x-permitted-cross-domain-policies",
            "referrer-policy",
            "cross-origin-embedder-policy",
            "cross-origin-opener-policy",
            "missing-content-type",
        )
        other = _line(
            template_id="waf-detect", matched_at="http://10.0.0.5/login.php", name="WAF Detection", severity="info"
        )
        headers_output = "\n".join(
            _line(
                template_id="http-missing-security-headers",
                matched_at="http://10.0.0.5/login.php",
                matcher_name=name,
                name="HTTP Missing Security Headers",
                severity="info",
            )
            for name in headers
        )
        findings = parse_nuclei_jsonl(f"{headers_output}\n{other}")
        assert len(findings) == 2  # the collapsed headers finding + the unrelated WAF one
        header_findings = [f for f in findings if f.title == "HTTP Missing Security Headers"]
        assert len(header_findings) == 1
        assert len(header_findings[0].evidence) == 10
