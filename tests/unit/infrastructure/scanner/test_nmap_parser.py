"""Nmap XML parser: comprehensive tests for parse_nmap_xml."""

from __future__ import annotations

from kingsec.domain import Severity
from kingsec.infrastructure.scanner.nmap_parser import _classify_port_severity, parse_nmap_xml

# ---------------------------------------------------------------------------
# Fixtures: sample XML outputs
# ---------------------------------------------------------------------------

_EMPTY_XML = '<?xml version="1.0"?>\n<nmaprun></nmaprun>'

_SINGLE_HOST_XML = """\
<?xml version="1.0" encoding="UTF-8"?>
<nmaprun scanner="nmap" args="nmap -sV -oX - 10.0.0.5">
  <host>
    <status state="up" reason="echo-reply"/>
    <address addr="10.0.0.5" addrtype="ipv4"/>
    <hostnames>
      <hostname name="example.com" type="PTR"/>
    </hostnames>
    <ports>
      <port protocol="tcp" portid="22">
        <state state="open" reason="syn-ack"/>
        <service name="ssh" product="OpenSSH" version="8.2p1"/>
      </port>
      <port protocol="tcp" portid="80">
        <state state="open" reason="syn-ack"/>
        <service name="http" product="nginx" version="1.18.0"/>
      </port>
    </ports>
  </host>
</nmaprun>
"""

_CLOSED_PORT_XML = """\
<?xml version="1.0" encoding="UTF-8"?>
<nmaprun>
  <host>
    <status state="up" reason="echo-reply"/>
    <address addr="10.0.0.5" addrtype="ipv4"/>
    <ports>
      <port protocol="tcp" portid="22">
        <state state="closed" reason="reset"/>
        <service name="ssh"/>
      </port>
    </ports>
  </host>
</nmaprun>
"""

_HOST_DOWN_XML = """\
<?xml version="1.0" encoding="UTF-8"?>
<nmaprun>
  <host>
    <status state="down" reason="no-response"/>
    <address addr="10.0.0.99" addrtype="ipv4"/>
  </host>
</nmaprun>
"""

_NO_VERSION_XML = """\
<?xml version="1.0" encoding="UTF-8"?>
<nmaprun>
  <host>
    <status state="up" reason="echo-reply"/>
    <address addr="10.0.0.5" addrtype="ipv4"/>
    <ports>
      <port protocol="tcp" portid="8080">
        <state state="open" reason="syn-ack"/>
        <service name="http-proxy"/>
      </port>
    </ports>
  </host>
</nmaprun>
"""

_SCRIPT_OUTPUT_XML = """\
<?xml version="1.0" encoding="UTF-8"?>
<nmaprun>
  <host>
    <status state="up" reason="echo-reply"/>
    <address addr="10.0.0.5" addrtype="ipv4"/>
    <ports>
      <port protocol="tcp" portid="443">
        <state state="open" reason="syn-ack"/>
        <service name="https" product="Apache" version="2.4.41"/>
        <script id="ssl-poodle" output="VULNERABLE: SSLv3 protocol"/>
        <script id="ssl-enum-ciphers" output="TLS 1.2: ..."/>
      </port>
    </ports>
  </host>
</nmaprun>
"""

_MULTI_HOST_XML = """\
<?xml version="1.0" encoding="UTF-8"?>
<nmaprun>
  <host>
    <status state="up" reason="echo-reply"/>
    <address addr="10.0.0.1" addrtype="ipv4"/>
    <ports>
      <port protocol="tcp" portid="80">
        <state state="open" reason="syn-ack"/>
        <service name="http"/>
      </port>
    </ports>
  </host>
  <host>
    <status state="up" reason="echo-reply"/>
    <address addr="10.0.0.2" addrtype="ipv4"/>
    <ports>
      <port protocol="tcp" portid="443">
        <state state="open" reason="syn-ack"/>
        <service name="https"/>
      </port>
    </ports>
  </host>
</nmaprun>
"""

_NO_HOSTNAME_XML = """\
<?xml version="1.0" encoding="UTF-8"?>
<nmaprun>
  <host>
    <status state="up" reason="echo-reply"/>
    <address addr="192.168.1.100" addrtype="ipv4"/>
    <ports>
      <port protocol="tcp" portid="3306">
        <state state="open" reason="syn-ack"/>
        <service name="mysql"/>
      </port>
    </ports>
  </host>
</nmaprun>
"""

_NO_SERVICES_XML = """\
<?xml version="1.0" encoding="UTF-8"?>
<nmaprun>
  <host>
    <status state="up" reason="echo-reply"/>
    <address addr="10.0.0.5" addrtype="ipv4"/>
  </host>
</nmaprun>
"""

EMPTY_OUTPUT = ""
WHITESPACE_OUTPUT = "   \n  \n  "


# ===========================================================================
# Tests
# ===========================================================================


class TestParseNmapXml:
    """Core parser behaviour."""

    def test_empty_output(self) -> None:
        assert parse_nmap_xml(EMPTY_OUTPUT) == []

    def test_whitespace_only_output(self) -> None:
        assert parse_nmap_xml(WHITESPACE_OUTPUT) == []

    def test_empty_xml(self) -> None:
        assert parse_nmap_xml(_EMPTY_XML) == []

    def test_malformed_xml(self) -> None:
        assert parse_nmap_xml("<broken><<>>") == []

    def test_single_host_two_ports(self) -> None:
        findings = parse_nmap_xml(_SINGLE_HOST_XML)
        assert len(findings) == 2
        titles = {f.title for f in findings}
        assert "Open port 22/tcp" in titles
        assert "Open port 80/tcp" in titles

    def test_ssh_port_with_version_is_medium(self) -> None:
        # Port 22/ssh is a medium-risk service class under the port-severity
        # model (routinely brute-forced) - not "Low because nmap found a
        # product banner", which was the old heuristic.
        findings = parse_nmap_xml(_SINGLE_HOST_XML)
        port22 = next(f for f in findings if "22" in f.title)
        assert port22.severity is Severity.MEDIUM

    def test_identified_unremarkable_service_is_low(self) -> None:
        # Port 8080/http-proxy: identified, no risk-class history -> Low.
        findings = parse_nmap_xml(_NO_VERSION_XML)
        assert len(findings) == 1
        assert findings[0].severity is Severity.LOW

    def test_closed_port_not_reported(self) -> None:
        findings = parse_nmap_xml(_CLOSED_PORT_XML)
        assert len(findings) == 0

    def test_host_down_not_reported(self) -> None:
        findings = parse_nmap_xml(_HOST_DOWN_XML)
        assert len(findings) == 0

    def test_multi_host(self) -> None:
        findings = parse_nmap_xml(_MULTI_HOST_XML)
        assert len(findings) == 2
        titles = {f.title for f in findings}
        assert "Open port 80/tcp" in titles
        assert "Open port 443/tcp" in titles

    def test_no_hostname_uses_addr(self) -> None:
        findings = parse_nmap_xml(_NO_HOSTNAME_XML)
        assert len(findings) == 1
        evidence = findings[0].evidence[0]
        assert "192.168.1.100" in evidence.summary

    def test_no_services_no_findings(self) -> None:
        findings = parse_nmap_xml(_NO_SERVICES_XML)
        assert len(findings) == 0


class TestScriptFindings:
    """Script output parsing and severity classification."""

    def test_script_produces_finding(self) -> None:
        findings = parse_nmap_xml(_SCRIPT_OUTPUT_XML)
        script_findings = [f for f in findings if f.title.startswith("Nmap script")]
        assert len(script_findings) == 2

    def test_ssl_poodle_is_high(self) -> None:
        findings = parse_nmap_xml(_SCRIPT_OUTPUT_XML)
        poodle = next(f for f in findings if "ssl-poodle" in f.title)
        assert poodle.severity is Severity.HIGH

    def test_ssl_enum_ciphers_is_medium(self) -> None:
        findings = parse_nmap_xml(_SCRIPT_OUTPUT_XML)
        enum = next(f for f in findings if "ssl-enum-ciphers" in f.title)
        assert enum.severity is Severity.MEDIUM

    def test_script_has_evidence(self) -> None:
        findings = parse_nmap_xml(_SCRIPT_OUTPUT_XML)
        poodle = next(f for f in findings if "ssl-poodle" in f.title)
        assert len(poodle.evidence) == 1
        assert "ssl-poodle" in poodle.evidence[0].summary


class TestSeverityClassification:
    """Severity heuristic for scripts."""

    def test_unknown_script_is_low(self) -> None:
        from kingsec.infrastructure.scanner.nmap_parser import _classify_script_severity

        assert _classify_script_severity("some-random-script") is Severity.LOW

    def test_heartbleed_is_high(self) -> None:
        from kingsec.infrastructure.scanner.nmap_parser import _classify_script_severity

        assert _classify_script_severity("ssl-heartbleed") is Severity.HIGH

    def test_dh_params_is_high(self) -> None:
        from kingsec.infrastructure.scanner.nmap_parser import _classify_script_severity

        assert _classify_script_severity("ssl-dh-params") is Severity.HIGH

    def test_http_vuln_is_medium(self) -> None:
        from kingsec.infrastructure.scanner.nmap_parser import _classify_script_severity

        assert _classify_script_severity("http-vuln-cve2021-12345") is Severity.MEDIUM

    def test_smb_vuln_is_medium(self) -> None:
        from kingsec.infrastructure.scanner.nmap_parser import _classify_script_severity

        assert _classify_script_severity("smb-vuln-ms17-010") is Severity.MEDIUM


class TestRemediationLookupStaysInSyncWithGeneratedTitles:
    """domain/report.py's generic_remediation_for() fallback table is keyed on
    this parser's exact generated title string, not a structured finding-type
    identifier - there isn't one anywhere in Finding/FindingSummary to key on
    instead (checked: neither carries anything beyond title/description/
    severity/status). That makes the match fragile to wording drift, with no
    signal if it silently breaks. This test is the safety net: it runs the
    real parser against a real fixture and feeds the real generated title
    into the real lookup, so a wording change on either side fails this test
    immediately instead of quietly falling back to "no guidance available"
    in production.
    """

    def test_open_port_title_still_matches_the_remediation_table(self) -> None:
        from kingsec.domain.report import generic_remediation_for

        # _SINGLE_HOST_XML has two open ports and no scripts, so every finding
        # it produces is an "open port" finding by construction - taken by
        # position, not by re-matching the very title text under test, so a
        # wording change of any kind (not just one that drops the word
        # "Open") still reaches the assertion below with a clear message
        # instead of failing earlier on an unrelated lookup.
        findings = parse_nmap_xml(_SINGLE_HOST_XML)
        assert len(findings) == 2
        open_port_finding = findings[0]

        rec = generic_remediation_for(open_port_finding.title, open_port_finding.severity)

        assert rec is not None, (
            f"nmap_parser.py's generated title {open_port_finding.title!r} no "
            "longer matches domain/report.py's _GENERIC_REMEDIATION_BY_TITLE_PREFIX "
            "table - update the table's prefix to match, or vice versa."
        )


_RISK_CLASS_XML = """\
<?xml version="1.0" encoding="UTF-8"?>
<nmaprun scanner="nmap" args="nmap -sV -oX - 10.0.0.9">
  <host>
    <status state="up" reason="echo-reply"/>
    <address addr="10.0.0.9" addrtype="ipv4"/>
    <ports>
      <port protocol="tcp" portid="3389">
        <state state="open" reason="syn-ack"/>
        <service name="ms-wbt-server"/>
      </port>
      <port protocol="tcp" portid="445">
        <state state="open" reason="syn-ack"/>
        <service name="microsoft-ds"/>
      </port>
      <port protocol="tcp" portid="9999">
        <state state="open" reason="syn-ack"/>
        <service name=""/>
      </port>
    </ports>
  </host>
</nmaprun>
"""


class TestPortSeverityModel:
    """The open-port severity model rates the service's risk class, not
    whether nmap fingerprinted a banner."""

    def test_rdp_by_port_is_high(self) -> None:
        severity, _ = _classify_port_severity("3389", "")
        assert severity is Severity.HIGH

    def test_rdp_by_service_name_on_odd_port_is_high(self) -> None:
        # Service-name match catches RDP moved off its well-known port.
        severity, _ = _classify_port_severity("8080", "ms-wbt-server")
        assert severity is Severity.HIGH

    def test_smb_telnet_vnc_databases_are_high(self) -> None:
        for port in ("23", "135", "139", "445", "1433", "3306", "5432", "5900", "6379", "9200", "27017"):
            severity, _ = _classify_port_severity(port, "")
            assert severity is Severity.HIGH, f"port {port} should be HIGH"

    def test_ssh_dns_snmp_are_medium(self) -> None:
        for port in ("22", "25", "53", "161", "389"):
            severity, _ = _classify_port_severity(port, "")
            assert severity is Severity.MEDIUM, f"port {port} should be MEDIUM"

    def test_identified_ordinary_service_is_low(self) -> None:
        for port, service in (("80", "http"), ("443", "https"), ("8080", "http-proxy")):
            severity, _ = _classify_port_severity(port, service)
            assert severity is Severity.LOW, f"port {port}/{service} should be LOW"

    def test_unidentified_service_is_informational(self) -> None:
        severity, _ = _classify_port_severity("9999", "")
        assert severity is Severity.INFORMATIONAL

    def test_non_numeric_portid_does_not_crash(self) -> None:
        severity, _ = _classify_port_severity("?", "http")
        assert severity is Severity.LOW
        severity, _ = _classify_port_severity("?", "")
        assert severity is Severity.INFORMATIONAL

    def test_rationale_is_recorded_in_description(self) -> None:
        findings = parse_nmap_xml(_RISK_CLASS_XML)
        rdp = next(f for f in findings if "3389" in f.title)
        assert rdp.severity is Severity.HIGH
        assert "Rated High" in rdp.description
        unknown = next(f for f in findings if "9999" in f.title)
        assert unknown.severity is Severity.INFORMATIONAL
        assert "Rated Informational" in unknown.description


class TestAffectedAsset:
    """Port findings carry the concrete host nmap probed, not the
    assessment-level target string."""

    def test_port_finding_carries_scanned_host(self) -> None:
        findings = parse_nmap_xml(_RISK_CLASS_XML)
        assert len(findings) == 3
        for finding in findings:
            assert finding.affected_asset == "10.0.0.9"

    def test_script_finding_carries_scanned_host(self) -> None:
        findings = parse_nmap_xml(_SCRIPT_OUTPUT_XML)
        script_findings = [f for f in findings if f.title.startswith("Nmap script:")]
        assert script_findings, "fixture should produce script findings"
        for finding in script_findings:
            assert finding.affected_asset == "10.0.0.5"

    def test_specific_remediation_entries_match_generated_titles(self) -> None:
        from kingsec.domain.report import generic_remediation_for

        findings = parse_nmap_xml(_RISK_CLASS_XML)
        rdp = next(f for f in findings if "3389" in f.title)
        rec = generic_remediation_for(rdp.title, rdp.severity)
        assert rec is not None
        assert "RDP" in rec.title or "RDP" in rec.description
        smb = next(f for f in findings if "445" in f.title)
        rec = generic_remediation_for(smb.title, smb.severity)
        assert rec is not None
        assert "SMB" in rec.title or "SMB" in rec.description
