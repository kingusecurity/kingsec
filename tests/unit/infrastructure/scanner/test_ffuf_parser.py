"""ffuf parser: comprehensive tests for parse_ffuf_json."""

from __future__ import annotations

import json
import random

from kingsec.domain import Severity, SeverityDemotionReason
from kingsec.infrastructure.scanner.ffuf_parser import _base_severity, parse_ffuf_json


def _record(
    *, fuzz: str = "x", status: int = 200, length: int = 100, url: str = "http://example.com/x",
    content_type: str = "text/plain",
) -> str:
    return json.dumps(
        {
            "input": {"FUZZ": fuzz},
            "status": status,
            "length": length,
            "words": length // 10,
            "lines": length // 50,
            "content-type": content_type,
            "redirectlocation": "",
            "url": url,
            "duration": 1000,
            "resultfile": "",
            "host": "example.com",
        }
    )

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

    def test_sensitive_extension_with_html_content_type_is_demoted_to_low(self) -> None:
        # Phase 2B-c Priority 1b (Defect 3): a 200 on /.env with an HTML
        # body is a generic app response, not a confirmed file disclosure -
        # this exact case (a real Juice Shop flood) is why Signal 1 exists.
        line = (
            '{"input":{"FUZZ":".env"},"status":200,"length":500,"words":30,'
            '"lines":10,"content-type":"text/html","redirectlocation":"",'
            '"url":"http://example.com/.env","duration":1000,'
            '"resultfile":"","host":"example.com"}'
        )
        findings = parse_ffuf_json(line)
        assert findings[0].severity is Severity.LOW
        assert findings[0].original_severity is Severity.HIGH
        assert findings[0].demotion_reason is SeverityDemotionReason.CONTENT_TYPE_MISMATCH

    def test_sensitive_extension_with_non_html_content_type_stays_high(self) -> None:
        # The same path, but a content-type a real .env file could
        # plausibly have - no content-type contradiction, no demotion.
        line = (
            '{"input":{"FUZZ":".env"},"status":200,"length":500,"words":30,'
            '"lines":10,"content-type":"text/plain","redirectlocation":"",'
            '"url":"http://example.com/.env","duration":1000,'
            '"resultfile":"","host":"example.com"}'
        )
        findings = parse_ffuf_json(line)
        assert findings[0].severity is Severity.HIGH
        assert findings[0].original_severity is None
        assert findings[0].demotion_reason is None

    def test_git_extension_with_html_content_type_is_demoted_to_low(self) -> None:
        line = (
            '{"input":{"FUZZ":".git"},"status":200,"length":890,"words":34,'
            '"lines":12,"content-type":"text/html","redirectlocation":"",'
            '"url":"http://example.com/.git","duration":1000,'
            '"resultfile":"","host":"example.com"}'
        )
        findings = parse_ffuf_json(line)
        assert findings[0].severity is Severity.LOW
        assert findings[0].original_severity is Severity.HIGH
        assert findings[0].demotion_reason is SeverityDemotionReason.CONTENT_TYPE_MISMATCH

    def test_git_subpath_is_high(self) -> None:
        line = (
            '{"input":{"FUZZ":"HEAD"},"status":200,"length":50,"words":5,'
            '"lines":2,"content-type":"text/plain","redirectlocation":"",'
            '"url":"http://example.com/.git/HEAD","duration":1000,'
            '"resultfile":"","host":"example.com"}'
        )
        findings = parse_ffuf_json(line)
        assert findings[0].severity is Severity.HIGH

    def test_gitignore_is_not_high(self) -> None:
        line = (
            '{"input":{"FUZZ":".gitignore"},"status":200,"length":100,"words":10,'
            '"lines":5,"content-type":"text/plain","redirectlocation":"",'
            '"url":"http://example.com/.gitignore","duration":1000,'
            '"resultfile":"","host":"example.com"}'
        )
        findings = parse_ffuf_json(line)
        assert findings[0].severity is Severity.LOW  # .gitignore is not .git

    def test_env_local_is_not_high(self) -> None:
        line = (
            '{"input":{"FUZZ":".env.local"},"status":200,"length":200,"words":15,'
            '"lines":5,"content-type":"text/plain","redirectlocation":"",'
            '"url":"http://example.com/.env.local","duration":1000,'
            '"resultfile":"","host":"example.com"}'
        )
        findings = parse_ffuf_json(line)
        assert findings[0].severity is Severity.LOW

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


class TestBroadenedSensitivePathPatterns:
    """Phase 2B-c Priority 1b (approved plan, Change 1): extensionless
    sensitive paths named directly from the real Run 2 flood - must be
    recognized as sensitive (HIGH) same as an extension match, independent
    of Signal 1 (non-HTML content-type here isolates that question)."""

    def test_git_head_is_sensitive(self) -> None:
        findings = parse_ffuf_json(_record(url="http://example.com/.git/HEAD"))
        assert findings[0].severity is Severity.HIGH

    def test_git_config_is_sensitive(self) -> None:
        findings = parse_ffuf_json(_record(url="http://example.com/.git/config"))
        assert findings[0].severity is Severity.HIGH

    def test_id_rsa_is_sensitive(self) -> None:
        findings = parse_ffuf_json(_record(url="http://example.com/id_rsa"))
        assert findings[0].severity is Severity.HIGH

    def test_aws_credentials_is_sensitive(self) -> None:
        findings = parse_ffuf_json(_record(url="http://example.com/.aws/credentials"))
        assert findings[0].severity is Severity.HIGH

    def test_cosign_key_is_sensitive(self) -> None:
        findings = parse_ffuf_json(_record(url="http://example.com/cosign.key"))
        assert findings[0].severity is Severity.HIGH

    def test_ws_ftp_log_is_sensitive(self) -> None:
        findings = parse_ffuf_json(_record(url="http://example.com/WS_FTP.LOG"))
        assert findings[0].severity is Severity.HIGH

    def test_broadened_paths_still_demote_on_html_content_type(self) -> None:
        findings = parse_ffuf_json(_record(url="http://example.com/id_rsa", content_type="text/html"))
        assert findings[0].severity is Severity.LOW
        assert findings[0].demotion_reason is SeverityDemotionReason.CONTENT_TYPE_MISMATCH


class TestSignal2BaselineShapeClustering:
    """Phase 2B-c Priority 1b (approved plan, Change 2): a large cluster of
    otherwise-sensitive/HIGH hits sharing one (status, length) shape is
    demoted, even with a non-HTML content-type (which would otherwise
    escape Signal 1 entirely) - this is the gobuster-equivalent signal,
    using only data ffuf already reports."""

    def test_dominant_shape_cluster_is_demoted(self) -> None:
        # 10 distinct sensitive paths, identical (status, length) - clears
        # both the >=5 occurrence and >=3% thresholds in a 10-result batch.
        lines = "\n".join(
            _record(fuzz=f"leak{i}", url=f"http://example.com/leak{i}.key", status=200, length=9216)
            for i in range(10)
        )
        findings = parse_ffuf_json(lines)
        assert len(findings) == 10
        assert all(f.severity is Severity.LOW for f in findings)
        assert all(f.original_severity is Severity.HIGH for f in findings)
        assert all(f.demotion_reason is SeverityDemotionReason.BASELINE_SHAPE_MATCH for f in findings)

    def test_below_occurrence_floor_not_demoted(self) -> None:
        # Only 4 - below the >=5 floor even though every one is sensitive.
        lines = "\n".join(
            _record(fuzz=f"leak{i}", url=f"http://example.com/leak{i}.key", status=200, length=9216)
            for i in range(4)
        )
        findings = parse_ffuf_json(lines)
        assert all(f.severity is Severity.HIGH for f in findings)
        assert all(f.demotion_reason is None for f in findings)

    def test_minority_shape_within_a_demoted_batch_is_unaffected(self) -> None:
        dominant = [
            _record(fuzz=f"leak{i}", url=f"http://example.com/leak{i}.key", status=200, length=9216)
            for i in range(10)
        ]
        minority = [_record(fuzz="unique", url="http://example.com/unique.key", status=200, length=42)]
        findings = parse_ffuf_json("\n".join(dominant + minority))

        by_fuzz = {f.description.rsplit("Fuzz: ", 1)[1]: f for f in findings}
        assert by_fuzz["unique"].severity is Severity.HIGH
        assert by_fuzz["unique"].demotion_reason is None
        assert all(
            by_fuzz[f"leak{i}"].demotion_reason is SeverityDemotionReason.BASELINE_SHAPE_MATCH for i in range(10)
        )

    def test_low_severity_results_never_join_the_candidate_population(self) -> None:
        # A large cluster of plain LOW (200, non-sensitive) results sharing
        # a shape must never be treated as a demotion candidate - they were
        # never MEDIUM+ to begin with, so there is nothing to demote.
        lines = "\n".join(
            _record(fuzz=f"page{i}", url=f"http://example.com/page{i}", status=200, length=9216) for i in range(20)
        )
        findings = parse_ffuf_json(lines)
        assert all(f.severity is Severity.LOW for f in findings)
        assert all(f.demotion_reason is None for f in findings)


class TestDowngradeOnlyInvariant:
    """Phase 2B-c Priority 1b (approved plan, invariant test): for every
    input, final severity must never exceed the path/status-only severity
    a reader relying only on the path name would compute. Verified over
    many generated inputs, not just the three worked examples above -
    ``_base_severity`` is called independently here, not reused from
    inside the parser, so a bug in the demotion wiring itself would still
    be caught."""

    def test_severity_never_exceeds_the_path_name_only_severity(self) -> None:
        rng = random.Random(20260913)  # noqa: S311 - deterministic test fuzzing, not cryptographic
        statuses = [200, 201, 204, 301, 302, 401, 403, 404, 500, 503]
        paths = [
            "x", "admin", "login", ".env", ".git/HEAD", ".git/config", "id_rsa", ".aws/credentials",
            "cosign.key", "WS_FTP.LOG", ".sql", ".bak", "normal/page", "dashboard/panel",
        ]
        content_types = ["text/html", "text/plain", "application/octet-stream", "", "application/json"]
        lengths = [0, 1, 42, 100, 1234, 9216, 50000]

        records = []
        for _ in range(500):
            status = rng.choice(statuses)
            path = rng.choice(paths)
            url = f"http://example.com/{path}"
            content_type = rng.choice(content_types)
            length = rng.choice(lengths)
            records.append(_record(fuzz=path, status=status, url=url, content_type=content_type, length=length))

        findings = parse_ffuf_json("\n".join(records))
        assert len(findings) == 500

        for finding, record_json in zip(findings, records, strict=True):
            record = json.loads(record_json)
            expected_path_name_only = _base_severity(record["status"], record["url"])
            assert finding.severity <= expected_path_name_only, (
                f"{finding.title!r} scored {finding.severity} above its path-name-only "
                f"severity {expected_path_name_only} - a demotion signal raised severity, "
                "which must never happen"
            )
