"""Nikto parser: comprehensive tests for parse_nikto_output."""

from __future__ import annotations

from kingsec.domain import Severity
from kingsec.infrastructure.scanner.nikto_parser import parse_nikto_output

# ---------------------------------------------------------------------------
# Fixtures: sample Nikto outputs
# ---------------------------------------------------------------------------

_EMPTY_OUTPUT = ""

_FULL_SCAN_OUTPUT = """\
- Nikto v2.5.0
---------------------------------------------------------------------------
+ Target IP:           10.0.0.5
+ Target Hostname:     example.com
+ Target Port:         80
+ Start Time: 2024-01-01 12:00:00
---------------------------------------------------------------------------
+ Server: Apache/2.4.41
+ /: The anti-clickjacking X-Frame-Options header is not present.
+ /: The X-Content-Type-Options header is not set.
+ /: Directory indexing found.
+ /admin/: Admin directory found.
+ OSVDB-3092: /admin/: Admin directory found.
+ OSVDB-3268: /icons/: Directory indexing found.
+ OSVDB-3238: /cgi-bin/test.cgi: Potential RCE vulnerability found.
+ /: Cookie without HttpOnly flag set.
+ /: Cookie without Secure flag set.
---------------------------------------------------------------------------
+ End Time:            2024-01-01 12:01:00
---------------------------------------------------------------------------
1 host(s) tested
"""

_SERVER_BANNER_ONLY = """\
---------------------------------------------------------------------------
+ Target IP:           10.0.0.5
+ Target Port:         80
+ Start Time: 2024-01-01 12:00:00
---------------------------------------------------------------------------
+ Server: nginx/1.18.0
---------------------------------------------------------------------------
+ End Time:            2024-01-01 12:00:30
---------------------------------------------------------------------------
1 host(s) tested
"""

_NO_FINDINGS_OUTPUT = """\
---------------------------------------------------------------------------
+ Target IP:           10.0.0.5
+ Target Port:         80
+ Start Time: 2024-01-01 12:00:00
---------------------------------------------------------------------------
---------------------------------------------------------------------------
+ End Time:            2024-01-01 12:00:10
---------------------------------------------------------------------------
1 host(s) tested
"""

_RCE_OUTPUT = """\
+ OSVDB-3238: /cgi-bin/test.cgi: Potential remote code execution found.
+ /cgi-bin/cmd.exe: Remote code execution via command injection.
+ /shell.jsp: Backdoor detected.
"""

_HEADER_MISSING_OUTPUT = """\
+ /: The anti-clickjacking X-Frame-Options header is not present.
+ /: The X-Content-Type-Options header is not set.
+ /: Content-Security-Policy header is not set.
"""

_DIRECTORY_OUTPUT = """\
+ /icons/: Directory indexing found.
+ /backup/: Backup directory found.
+ /config/: Config file found.
+ /logs/: Sensitive log file found.
"""


# ===========================================================================
# Tests
# ===========================================================================


class TestParseNiktoOutput:
    """Core parser behaviour."""

    def test_empty_output(self) -> None:
        assert parse_nikto_output("") == []

    def test_whitespace_only_output(self) -> None:
        assert parse_nikto_output("   \n  \n  ") == []

    def test_no_findings_output(self) -> None:
        findings = parse_nikto_output(_NO_FINDINGS_OUTPUT)
        assert len(findings) == 0

    def test_full_scan_finds_all_issues(self) -> None:
        findings = parse_nikto_output(_FULL_SCAN_OUTPUT)
        assert len(findings) == 10

    def test_separator_lines_ignored(self) -> None:
        findings = parse_nikto_output(_FULL_SCAN_OUTPUT)
        for f in findings:
            assert not f.title.startswith("-")

    def test_metadata_lines_ignored(self) -> None:
        findings = parse_nikto_output(_FULL_SCAN_OUTPUT)
        for f in findings:
            assert "Target IP" not in f.title
            assert "Start Time" not in f.title
            assert "End Time" not in f.title
            assert "host(s) tested" not in f.title


class TestSeverityClassification:
    """Severity mapping for different finding types."""

    def test_server_banner_is_informational(self) -> None:
        findings = parse_nikto_output(_SERVER_BANNER_ONLY)
        assert len(findings) == 1
        assert findings[0].severity is Severity.INFORMATIONAL

    def test_missing_header_is_low(self) -> None:
        findings = parse_nikto_output(_HEADER_MISSING_OUTPUT)
        assert len(findings) == 3
        for f in findings:
            assert f.severity is Severity.LOW

    def test_directory_indexing_is_medium(self) -> None:
        findings = parse_nikto_output(_DIRECTORY_OUTPUT)
        assert len(findings) == 4
        for f in findings:
            assert f.severity is Severity.MEDIUM

    def test_osvdb_entry_is_critical_when_rce(self) -> None:
        findings = parse_nikto_output(_RCE_OUTPUT)
        osvdb_findings = [f for f in findings if "OSVDB" in f.title]
        assert len(osvdb_findings) == 1
        # This OSVDB entry mentions "remote code execution" so it gets CRITICAL
        assert osvdb_findings[0].severity is Severity.CRITICAL

    def test_rce_is_critical(self) -> None:
        findings = parse_nikto_output(_RCE_OUTPUT)
        rce = [f for f in findings if "remote code execution" in f.title.lower()
               or "command injection" in f.title.lower()]
        assert len(rce) == 2
        for f in rce:
            assert f.severity is Severity.CRITICAL

    def test_backdoor_is_critical(self) -> None:
        findings = parse_nikto_output(_RCE_OUTPUT)
        backdoor = [f for f in findings if "backdoor" in f.title.lower()]
        assert len(backdoor) == 1
        assert backdoor[0].severity is Severity.CRITICAL

    def test_admin_directory_is_medium(self) -> None:
        findings = parse_nikto_output(_FULL_SCAN_OUTPUT)
        admin = [f for f in findings if "admin" in f.title.lower()
                 and "OSVDB" not in f.title]
        assert len(admin) == 1
        assert admin[0].severity is Severity.MEDIUM


class TestEvidence:
    """Evidence is attached to every finding."""

    def test_all_findings_have_evidence(self) -> None:
        findings = parse_nikto_output(_FULL_SCAN_OUTPUT)
        for f in findings:
            assert len(f.evidence) == 1

    def test_evidence_contains_raw_line(self) -> None:
        findings = parse_nikto_output(_FULL_SCAN_OUTPUT)
        for f in findings:
            assert f.evidence[0].detail.startswith("raw: +")
