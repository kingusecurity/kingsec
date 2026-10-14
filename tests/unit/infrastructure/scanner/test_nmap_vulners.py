"""Nmap Vulners CVE correlation: parser, adapter flag, and honesty labelling."""

from __future__ import annotations

from kingsec.domain import Severity, Target, TargetType
from kingsec.infrastructure.config.models import NmapSettings
from kingsec.infrastructure.scanner.nmap import NmapScannerAdapter, _dedupe_findings
from kingsec.infrastructure.scanner.nmap_parser import _cvss_to_severity, parse_nmap_xml
from kingsec.infrastructure.scanner.runner import CommandResult
from tests.unit.infrastructure.scanner.conftest import FakeRunner

# nmap entity-encodes newlines/tabs inside the script output attribute
# (&#xa; / &#x9;); the XML parser decodes them back before we see them.
# The fixture mirrors that exactly - literal newlines in the attribute
# would be normalised to spaces by XML parsing and would NOT exercise
# the real code path.
_VULNERS_XML = """\
<?xml version="1.0" encoding="UTF-8"?>
<nmaprun scanner="nmap" args="nmap -sV --script vulners -oX - 10.0.0.5">
  <host>
    <status state="up" reason="echo-reply"/>
    <address addr="10.0.0.5" addrtype="ipv4"/>
    <ports>
      <port protocol="tcp" portid="443">
        <state state="open" reason="syn-ack"/>
        <service name="https" product="Apache httpd" version="2.4.41"/>
        <script id="vulners" output="&#xa;  cpe:/a:apache:http_server:2.4.41: &#xa;  &#x9;CVE-2021-44790&#x9;9.8&#x9;https://vulners.com/cve/CVE-2021-44790&#xa;  &#x9;CVE-2022-23943&#x9;7.5&#x9;https://vulners.com/cve/CVE-2022-23943&#xa;  &#x9;CVE-2020-11984&#x9;5.3&#x9;https://vulners.com/cve/CVE-2020-11984&#xa;  &#x9;CVE-2019-10092&#x9;2.1&#x9;https://vulners.com/cve/CVE-2019-10092&#xa;"/>
      </port>
    </ports>
  </host>
</nmaprun>
"""

# Same CVE listed under two CPEs for one port - must collapse to one finding.
_VULNERS_DUP_XML = """\
<?xml version="1.0" encoding="UTF-8"?>
<nmaprun>
  <host>
    <status state="up" reason="echo-reply"/>
    <address addr="10.0.0.5" addrtype="ipv4"/>
    <ports>
      <port protocol="tcp" portid="443">
        <state state="open" reason="syn-ack"/>
        <service name="https" product="Apache httpd" version="2.4.41"/>
        <script id="vulners" output="&#xa;  cpe:/a:apache:http_server:2.4.41: &#xa;  &#x9;CVE-2021-44790&#x9;9.8&#x9;https://vulners.com/cve/CVE-2021-44790&#xa;  cpe:/a:apache:http_server:2.4.41::~~~: &#xa;  &#x9;CVE-2021-44790&#x9;9.8&#x9;https://vulners.com/cve/CVE-2021-44790&#xa;"/>
      </port>
    </ports>
  </host>
</nmaprun>
"""

_VULNERS_ERROR_XML = """\
<?xml version="1.0" encoding="UTF-8"?>
<nmaprun>
  <host>
    <status state="up" reason="echo-reply"/>
    <address addr="10.0.0.5" addrtype="ipv4"/>
    <ports>
      <port protocol="tcp" portid="443">
        <state state="open" reason="syn-ack"/>
        <service name="https" product="Apache httpd" version="2.4.41"/>
        <script id="vulners" output="&#xa;  ERROR: API request failed&#xa;"/>
      </port>
    </ports>
  </host>
</nmaprun>
"""

_TARGET = Target("10.0.0.5", TargetType.IP_ADDRESS)


# ---------------------------------------------------------------------------
# Parser: CVE extraction
# ---------------------------------------------------------------------------


def test_vulners_script_yields_one_finding_per_cve():
    findings = parse_nmap_xml(_VULNERS_XML)
    cve_findings = [f for f in findings if f.title.startswith("CVE-")]
    assert len(cve_findings) == 4
    assert {f.cve_ids[0] for f in cve_findings} == {
        "CVE-2021-44790",
        "CVE-2022-23943",
        "CVE-2020-11984",
        "CVE-2019-10092",
    }


def test_vulners_findings_carry_cvss_and_severity():
    findings = parse_nmap_xml(_VULNERS_XML)
    by_cve = {f.cve_ids[0]: f for f in findings if f.title.startswith("CVE-")}
    assert by_cve["CVE-2021-44790"].cvss_score == 9.8
    assert by_cve["CVE-2021-44790"].severity == Severity.CRITICAL
    assert by_cve["CVE-2022-23943"].cvss_score == 7.5
    assert by_cve["CVE-2022-23943"].severity == Severity.HIGH
    assert by_cve["CVE-2020-11984"].cvss_score == 5.3
    assert by_cve["CVE-2020-11984"].severity == Severity.MEDIUM
    assert by_cve["CVE-2019-10092"].cvss_score == 2.1
    assert by_cve["CVE-2019-10092"].severity == Severity.LOW


def test_vulners_findings_are_labelled_version_correlated():
    findings = parse_nmap_xml(_VULNERS_XML)
    cve_findings = [f for f in findings if f.title.startswith("CVE-")]
    assert cve_findings, "expected CVE findings"
    for finding in cve_findings:
        assert "(version-correlated)" in finding.title
        assert "NOT actively confirmed" in finding.description
        assert "backport" in finding.description.lower()
        assert "version-match only, not actively confirmed" in finding.evidence[0].detail


def test_vulners_script_does_not_emit_generic_script_finding():
    findings = parse_nmap_xml(_VULNERS_XML)
    assert not [f for f in findings if f.title == "Nmap script: vulners"]


def test_vulners_duplicate_cve_across_cpes_deduped():
    findings = parse_nmap_xml(_VULNERS_DUP_XML)
    cve_findings = [f for f in findings if f.title.startswith("CVE-")]
    assert len(cve_findings) == 1
    assert cve_findings[0].cve_ids == ("CVE-2021-44790",)


def test_vulners_error_output_yields_no_findings_and_no_crash():
    findings = parse_nmap_xml(_VULNERS_ERROR_XML)
    assert not [f for f in findings if f.title.startswith("CVE-")]
    # The open port itself is still reported.
    assert any(f.title == "Open port 443/tcp" for f in findings)


def test_vulners_empty_output_yields_no_findings():
    xml = _VULNERS_ERROR_XML.replace(
        'output="&#xa;  ERROR: API request failed&#xa;"', 'output="&#xa;"'
    )
    findings = parse_nmap_xml(xml)
    assert not [f for f in findings if f.title.startswith("CVE-")]


def test_cvss_severity_bands():
    assert _cvss_to_severity(10.0) == Severity.CRITICAL
    assert _cvss_to_severity(9.0) == Severity.CRITICAL
    assert _cvss_to_severity(8.9) == Severity.HIGH
    assert _cvss_to_severity(7.0) == Severity.HIGH
    assert _cvss_to_severity(6.9) == Severity.MEDIUM
    assert _cvss_to_severity(4.0) == Severity.MEDIUM
    assert _cvss_to_severity(3.9) == Severity.LOW
    assert _cvss_to_severity(0.1) == Severity.LOW
    assert _cvss_to_severity(0.0) == Severity.INFORMATIONAL


# ---------------------------------------------------------------------------
# Adapter: opt-in flag, arg building, warnings
# ---------------------------------------------------------------------------


def test_vulners_script_disabled_by_default():
    assert NmapSettings().vulners_script_enabled is False


def test_vulners_script_flag_absent_by_default():
    runner = FakeRunner(CommandResult(0, _VULNERS_XML, "", 1.0))
    adapter = NmapScannerAdapter(NmapSettings(), runner=runner)
    adapter.scan(_TARGET)
    args = runner.calls[0][0]
    assert "--script" not in args
    assert "vulners" not in args
    assert adapter.last_scan_warnings() == ()


def test_vulners_script_flag_present_when_enabled():
    runner = FakeRunner(CommandResult(0, _VULNERS_XML, "", 1.0))
    adapter = NmapScannerAdapter(NmapSettings(vulners_script_enabled=True), runner=runner)
    findings = adapter.scan(_TARGET)
    args = runner.calls[0][0]
    assert "--script" in args
    assert "vulners" in args[args.index("--script") + 1]
    # End-to-end through the adapter: CVE findings survive.
    assert any(f.title.startswith("CVE-2021-44790") for f in findings)


def test_vulners_enabled_adds_coverage_warning():
    runner = FakeRunner(CommandResult(0, _VULNERS_XML, "", 1.0))
    adapter = NmapScannerAdapter(NmapSettings(vulners_script_enabled=True), runner=runner)
    adapter.scan(_TARGET)
    warnings = adapter.last_scan_warnings()
    assert len(warnings) == 1
    assert "version-matched" in warnings[0]
    assert "not actively confirmed" in warnings[0]


# ---------------------------------------------------------------------------
# Two-invocation dedupe (URL targets run nmap twice)
# ---------------------------------------------------------------------------


def test_dedupe_collapses_duplicate_vulners_cve_findings():
    findings = parse_nmap_xml(_VULNERS_XML)
    doubled = tuple(findings) + tuple(findings)
    deduped = _dedupe_findings(doubled)
    cve_titles = [f.title for f in deduped if f.title.startswith("CVE-")]
    assert len(cve_titles) == len(set(cve_titles)) == 4
    # Open-port dedupe still works alongside.
    assert len([f for f in deduped if f.title == "Open port 443/tcp"]) == 1
