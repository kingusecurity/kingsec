"""Gobuster parser: comprehensive tests for parse_gobuster_output."""

from __future__ import annotations

import random

from kingsec.domain import Severity, SeverityDemotionReason
from kingsec.infrastructure.scanner.gobuster_parser import _base_severity, parse_gobuster_output

# ---------------------------------------------------------------------------
# Fixtures: sample Gobuster outputs
# ---------------------------------------------------------------------------

_EMPTY_OUTPUT = ""

_FULL_DIR_OUTPUT = """\
Gobuster v3.6.0
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@firefart)
=============================================================
=============================================================
Gobuster v3.6.0
=============================================================
[+] Url:                     http://example.com
[+] Method:                  GET
[+] Threads:                 10
[+] Wordlist:                /usr/share/wordlists/common.txt
[+] Status codes:            200,204,301,302,307,401,403
[+] Content Size:            1234
[+] Timeout:                 10s
=============================================================
Starting gobuster in directory enumeration mode
=============================================================
/admin                 (Status: 200) [Size: 1234]
/backup                (Status: 200) [Size: 890]
/.git                  (Status: 200) [Size: 567]
/login                 (Status: 301) [Size: 0]
/dashboard             (Status: 403) [Size: 512]
/static                (Status: 200) [Size: 2345]
/config                (Status: 500) [Size: 100]
/api                   (Status: 201) [Size: 456]
=============================================================
Finished
=============================================================
"""

_NO_FINDINGS_OUTPUT = """\
Gobuster v3.6.0
=============================================================
Starting gobuster in directory enumeration mode
=============================================================
=============================================================
Finished
=============================================================
"""

_SINGLE_FINDING_OUTPUT = """\
/test-page            (Status: 200) [Size: 1234]
"""

_REDIRECT_OUTPUT = """\
/old-page             (Status: 302) [Size: 0]
/new-page             (Status: 301) [Size: 0]
"""

_AUTH_OUTPUT = """\
/auth                 (Status: 401) [Size: 512]
/forbidden            (Status: 403) [Size: 512]
"""

_ERROR_OUTPUT = """\
/crash                (Status: 500) [Size: 100]
/error                (Status: 502) [Size: 100]
"""

_SENSITIVE_PATH_OUTPUT = """\
/.env                 (Status: 200) [Size: 234]
/.git/HEAD            (Status: 200) [Size: 56]
/backup               (Status: 200) [Size: 890]
/config               (Status: 200) [Size: 456]
"""

_ADMIN_PATH_OUTPUT = """\
/admin                (Status: 200) [Size: 1234]
/wp-admin             (Status: 200) [Size: 1234]
/dashboard            (Status: 200) [Size: 1234]
/login                (Status: 200) [Size: 1234]
"""


# ===========================================================================
# Tests
# ===========================================================================


class TestParseGobusterOutput:
    """Core parser behaviour."""

    def test_empty_output(self) -> None:
        assert parse_gobuster_output("") == []

    def test_whitespace_only_output(self) -> None:
        assert parse_gobuster_output("   \n  \n  ") == []

    def test_no_findings_output(self) -> None:
        findings = parse_gobuster_output(_NO_FINDINGS_OUTPUT)
        assert len(findings) == 0

    def test_full_scan_finds_all_issues(self) -> None:
        findings = parse_gobuster_output(_FULL_DIR_OUTPUT)
        assert len(findings) == 8

    def test_separator_lines_ignored(self) -> None:
        findings = parse_gobuster_output(_FULL_DIR_OUTPUT)
        for f in findings:
            assert "=" * 3 not in f.title

    def test_metadata_lines_ignored(self) -> None:
        findings = parse_gobuster_output(_FULL_DIR_OUTPUT)
        for f in findings:
            assert "Gobuster v" not in f.title
            assert "Starting gobuster" not in f.title
            assert "Finished" not in f.title

    def test_single_finding(self) -> None:
        findings = parse_gobuster_output(_SINGLE_FINDING_OUTPUT)
        assert len(findings) == 1
        assert "200" in findings[0].title
        assert "/test-page" in findings[0].title


class TestSeverityClassification:
    """Severity mapping for different HTTP status codes."""

    def test_200_is_low(self) -> None:
        findings = parse_gobuster_output(_SINGLE_FINDING_OUTPUT)
        assert len(findings) == 1
        assert findings[0].severity is Severity.LOW

    def test_301_is_informational(self) -> None:
        findings = parse_gobuster_output(_REDIRECT_OUTPUT)
        assert len(findings) == 2
        for f in findings:
            assert f.severity is Severity.INFORMATIONAL

    def test_401_is_medium(self) -> None:
        findings = parse_gobuster_output(_AUTH_OUTPUT)
        assert len(findings) == 2
        for f in findings:
            assert f.severity is Severity.MEDIUM

    def test_500_is_high(self) -> None:
        findings = parse_gobuster_output(_ERROR_OUTPUT)
        assert len(findings) == 2
        for f in findings:
            assert f.severity is Severity.HIGH

    def test_sensitive_path_is_high(self) -> None:
        findings = parse_gobuster_output(_SENSITIVE_PATH_OUTPUT)
        assert len(findings) == 4
        for f in findings:
            assert f.severity is Severity.HIGH

    def test_admin_path_is_medium(self) -> None:
        findings = parse_gobuster_output(_ADMIN_PATH_OUTPUT)
        assert len(findings) == 4
        for f in findings:
            assert f.severity is Severity.MEDIUM

    def test_dotfile_path_is_high(self) -> None:
        output = "/.env                 (Status: 200) [Size: 234]\n"
        findings = parse_gobuster_output(output)
        assert len(findings) == 1
        assert findings[0].severity is Severity.HIGH


class TestEvidence:
    """Evidence is attached to every finding."""

    def test_all_findings_have_evidence(self) -> None:
        findings = parse_gobuster_output(_FULL_DIR_OUTPUT)
        for f in findings:
            assert len(f.evidence) == 1

    def test_evidence_contains_path(self) -> None:
        findings = parse_gobuster_output(_FULL_DIR_OUTPUT)
        for f in findings:
            assert "Gobuster:" in f.evidence[0].summary


class TestBroadenedSensitivePathPatterns:
    """Phase 2B-c Priority 1b (approved plan, Change 1): same broadened,
    extensionless sensitive-path list as ffuf_parser.py."""

    def test_git_head_is_sensitive(self) -> None:
        findings = parse_gobuster_output("/.git/HEAD            (Status: 200) [Size: 56]\n")
        assert findings[0].severity is Severity.HIGH

    def test_id_rsa_is_sensitive(self) -> None:
        findings = parse_gobuster_output("/id_rsa               (Status: 200) [Size: 1675]\n")
        assert findings[0].severity is Severity.HIGH

    def test_aws_credentials_is_sensitive(self) -> None:
        findings = parse_gobuster_output("/.aws/credentials     (Status: 200) [Size: 120]\n")
        assert findings[0].severity is Severity.HIGH

    def test_cosign_key_is_sensitive(self) -> None:
        findings = parse_gobuster_output("/cosign.key           (Status: 200) [Size: 800]\n")
        assert findings[0].severity is Severity.HIGH

    def test_ws_ftp_log_is_sensitive(self) -> None:
        findings = parse_gobuster_output("/WS_FTP.LOG           (Status: 200) [Size: 300]\n")
        assert findings[0].severity is Severity.HIGH


class TestSignal2BaselineShapeClustering:
    """Phase 2B-c Priority 1b (approved plan, Change 2): gobuster has no
    Content-Type field (Signal 1 doesn't apply), but a large cluster of
    otherwise-sensitive/HIGH hits sharing one (status, size) shape is
    still demoted via the shared baseline-shape signal."""

    def test_dominant_shape_cluster_is_demoted(self) -> None:
        # /.leak{i} - dot-prefixed, so each is independently sensitive
        # (lower_path.startswith("/.")) yet a distinct path.
        lines = "\n".join(f"/.leak{i}            (Status: 200) [Size: 9216]" for i in range(10))
        findings = parse_gobuster_output(lines)
        assert len(findings) == 10
        assert all(f.severity is Severity.LOW for f in findings)
        assert all(f.original_severity is Severity.HIGH for f in findings)
        assert all(f.demotion_reason is SeverityDemotionReason.BASELINE_SHAPE_MATCH for f in findings)

    def test_below_occurrence_floor_not_demoted(self) -> None:
        lines = "\n".join(f"/.leak{i}            (Status: 200) [Size: 9216]" for i in range(4))
        findings = parse_gobuster_output(lines)
        assert all(f.severity is Severity.HIGH for f in findings)
        assert all(f.demotion_reason is None for f in findings)

    def test_distinct_sizes_never_cluster(self) -> None:
        # The existing sensitive-path fixture (_SENSITIVE_PATH_OUTPUT) has 4
        # distinct sizes - confirms Signal 2 never fires on genuinely
        # distinct findings, only on a real shared shape.
        findings = parse_gobuster_output(_SENSITIVE_PATH_OUTPUT)
        assert len(findings) == 4
        assert all(f.severity is Severity.HIGH for f in findings)
        assert all(f.demotion_reason is None for f in findings)


class TestDowngradeOnlyInvariant:
    """Phase 2B-c Priority 1b (approved plan, invariant test): final
    severity must never exceed the path/status-only severity, verified
    over many generated inputs - ``_base_severity`` is recomputed
    independently here, not reused from inside the parser."""

    def test_severity_never_exceeds_the_path_name_only_severity(self) -> None:
        rng = random.Random(20260913)  # noqa: S311 - deterministic test fuzzing, not cryptographic
        statuses = [200, 201, 204, 301, 302, 401, 403, 404, 500, 503]
        paths = [
            "/x", "/admin", "/login", "/.env", "/.git/HEAD", "/.git/config", "/id_rsa",
            "/.aws/credentials", "/cosign.key", "/WS_FTP.LOG", "/sql", "/backup",
            "/normal/page", "/dashboard/panel",
        ]
        sizes = [0, 1, 42, 100, 1234, 9216, 50000]

        records = []
        for _ in range(500):
            status = rng.choice(statuses)
            path = rng.choice(paths)
            size = rng.choice(sizes)
            records.append((path, status, size))

        output = "\n".join(f"{path}            (Status: {status}) [Size: {size}]" for path, status, size in records)
        findings = parse_gobuster_output(output)
        assert len(findings) == 500

        for finding, (path, status, _size) in zip(findings, records, strict=True):
            expected_path_name_only = _base_severity(status, path)
            assert finding.severity <= expected_path_name_only, (
                f"{finding.title!r} scored {finding.severity} above its path-name-only "
                f"severity {expected_path_name_only} - a demotion signal raised severity, "
                "which must never happen"
            )
