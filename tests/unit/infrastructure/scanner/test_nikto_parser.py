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

# Regression: live 2026-10-12 proof run — Nikto's own status lines were
# emitted as findings, and "force" in the CGI notice matched the RCE
# pattern, producing a bogus CRITICAL finding at the top of the report.
_STATUS_LINES_OUTPUT = """\
+ No CGI Directories found (use '-C all' to force check all possible dirs). CGI tests skipped.
+ 8026 requests: 0 errors and 13 items reported on the remote host
+ 1 host(s) tested
+ Server: DemoWeb/2.4.1
"""

# Regression: live 2026-10-14 production report (asmt-299b600794c749859c3a7be9c77be1ac) —
# Nikto 2.5's modern summary format ("Scan terminated: ...") slipped past the
# old "\\d+ requests:"-anchored skip pattern and shipped as finding #45, and
# Nikto's un-stringified Perl reference ("Allowed HTTP Methods: ARRAY(0x...)")
# shipped as finding #43.
_MODERN_STATUS_LINES_OUTPUT = """\
+ Scan terminated: 19 errors and 26 items reported on the remote host
+ 1 host(s) tested
+ [999990] OPTIONS: Allowed HTTP Methods: ARRAY(0x5638176e5f80) .
+ Server: DemoWeb/2.4.1
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
        rce = [
            f for f in findings if "remote code execution" in f.title.lower() or "command injection" in f.title.lower()
        ]
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
        admin = [f for f in findings if "admin" in f.title.lower() and "OSVDB" not in f.title]
        assert len(admin) == 1
        assert admin[0].severity is Severity.MEDIUM

    def test_scanner_status_lines_are_not_findings(self) -> None:
        # Nikto's own run-status lines must never become findings, no
        # matter what severity words they happen to contain.
        findings = parse_nikto_output(_STATUS_LINES_OUTPUT)
        titles = [f.title for f in findings]
        assert not any("CGI" in t for t in titles)
        assert not any("requests:" in t for t in titles)
        assert not any("host(s) tested" in t for t in titles)
        # Only the real banner line survives.
        assert len(findings) == 1
        assert findings[0].severity is Severity.INFORMATIONAL

    def test_force_does_not_match_rce(self) -> None:
        # "force" contains the letters r-c-e but is not an RCE indicator.
        findings = parse_nikto_output("+ /some/path: try to force check all dirs.\n")
        assert len(findings) == 1
        assert findings[0].severity is not Severity.CRITICAL

    def test_modern_scan_terminated_summary_is_not_a_finding(self) -> None:
        # Nikto 2.5+ prints "Scan terminated: N errors and M items reported"
        # (no "requests:" prefix) - it describes the scanner's own run.
        findings = parse_nikto_output("+ Scan terminated: 19 errors and 26 items reported on the remote host\n")
        assert findings == []

    def test_array_reference_line_is_not_a_finding(self) -> None:
        # An un-stringified Perl reference is a scanner-side rendering bug,
        # not a result about the target.
        findings = parse_nikto_output("+ [999990] OPTIONS: Allowed HTTP Methods: ARRAY(0x5638176e5f80) .\n")
        assert findings == []

    def test_modern_status_lines_leave_only_real_findings(self) -> None:
        findings = parse_nikto_output(_MODERN_STATUS_LINES_OUTPUT)
        titles = [f.title for f in findings]
        assert not any("Scan terminated" in t for t in titles)
        assert not any("ARRAY(0x" in t for t in titles)
        assert not any("host(s) tested" in t for t in titles)
        # Only the real banner line survives.
        assert len(findings) == 1
        assert findings[0].severity is Severity.INFORMATIONAL


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
