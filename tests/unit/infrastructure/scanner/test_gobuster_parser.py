"""Gobuster parser: comprehensive tests for parse_gobuster_output."""

from __future__ import annotations

from kingsec.domain import Severity
from kingsec.infrastructure.scanner.gobuster_parser import parse_gobuster_output

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
