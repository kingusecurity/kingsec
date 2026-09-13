"""NmapPlugin: metadata, capabilities, availability, scan delegation, and provisioning."""

from __future__ import annotations

import pytest

from kingsec.application.ports.scanner_plugin import ScannerPluginPort
from kingsec.domain import (
    PluginConfig,
    ScanCategory,
    ScannerId,
    ScannerRequirement,
    ScannerResult,
    Severity,
    Target,
    TargetType,
)
from kingsec.infrastructure.config.models import NmapSettings
from kingsec.infrastructure.scanner.errors import BINARY_ABSENT_USER_MESSAGE, ScannerExecutionError
from kingsec.infrastructure.scanner.plugins.nmap import NmapPlugin
from kingsec.infrastructure.scanner.runner import CommandResult
from tests.unit.infrastructure.scanner.conftest import FakeRunner

_TARGET = Target("10.0.0.5", TargetType.IP_ADDRESS)

_SAMPLE_XML = """\
<?xml version="1.0" encoding="UTF-8"?>
<nmaprun>
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
    </ports>
  </host>
</nmaprun>
"""


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _make_plugin(
    *,
    binary_path: str = "nmap",
    runner: FakeRunner | None = None,
) -> NmapPlugin:
    settings = NmapSettings(binary_path=binary_path)
    return NmapPlugin(settings, runner=runner)


# ===========================================================================
# Metadata
# ===========================================================================


class TestMetadata:
    def test_plugin_id(self) -> None:
        assert _make_plugin().metadata().id == ScannerId("nmap")

    def test_plugin_name(self) -> None:
        assert _make_plugin().metadata().name == "Nmap Scanner"

    def test_plugin_version(self) -> None:
        assert _make_plugin().metadata().version == "1.0.0"

    def test_plugin_api_version(self) -> None:
        assert _make_plugin().metadata().api_version == "1.0"

    def test_plugin_author(self) -> None:
        assert _make_plugin().metadata().author == "KingSec"

    def test_is_scanner_plugin_port(self) -> None:
        assert isinstance(_make_plugin(), ScannerPluginPort)


# ===========================================================================
# Capabilities
# ===========================================================================


class TestCapabilities:
    def test_declares_reachable_host_and_network_range(self) -> None:
        caps = _make_plugin().capabilities()
        assert len(caps) == 2
        requirements = {c.requirement for c in caps}
        assert requirements == {ScannerRequirement.REACHABLE_HOST, ScannerRequirement.NETWORK_RANGE}

    def test_discovery_category(self) -> None:
        caps = _make_plugin().capabilities()
        assert ScanCategory.DISCOVERY in caps[0].scan_categories

    def test_configuration_category(self) -> None:
        caps = _make_plugin().capabilities()
        assert ScanCategory.CONFIGURATION in caps[0].scan_categories

    def test_no_vulnerability_category(self) -> None:
        caps = _make_plugin().capabilities()
        assert ScanCategory.VULNERABILITY not in caps[0].scan_categories

    def test_raw_text_output(self) -> None:
        from kingsec.domain import OutputFormat

        caps = _make_plugin().capabilities()
        assert caps[0].output_format is OutputFormat.RAW_TEXT


# ===========================================================================
# Availability
# ===========================================================================


class TestAvailability:
    def test_available_when_binary_found(self) -> None:
        plugin = _make_plugin(binary_path="python")
        avail = plugin.is_available()
        assert avail.available is True
        assert avail.reason is None

    def test_unavailable_when_binary_missing(self) -> None:
        plugin = _make_plugin(binary_path="definitely-not-nmap-xyz")
        avail = plugin.is_available()
        assert avail.available is False
        assert avail.reason is not None
        # Phase 08: this assertion previously checked that the configured
        # binary path LEAKED into the reason string - itself the exact
        # class of disclosure Phase 08 closes (§2's security constraint).
        # Deliberately replaced, not weakened: the reason must NOT contain
        # the configured value, and must be the shared safe message every
        # scanner's binary-absent case now uses.
        assert "definitely-not-nmap-xyz" not in avail.reason
        assert avail.reason == BINARY_ABSENT_USER_MESSAGE


# ===========================================================================
# Scan delegation
# ===========================================================================


class TestScan:
    def test_delegates_to_adapter(self) -> None:
        runner = FakeRunner(CommandResult(0, _SAMPLE_XML, "", 0.5))
        plugin = _make_plugin(runner=runner)
        result = plugin.scan(_TARGET, PluginConfig())
        assert isinstance(result, ScannerResult)
        assert result.scanner_id == ScannerId("nmap")
        assert len(result.findings) == 1
        assert result.findings[0].severity is Severity.LOW

    def test_adapter_exceptions_propagated(self) -> None:
        runner = FakeRunner(CommandResult(1, "", "error", 0.1))
        plugin = _make_plugin(runner=runner)
        with pytest.raises(ScannerExecutionError):
            plugin.scan(_TARGET, PluginConfig())

    def test_scanner_result_returned_unchanged(self) -> None:
        runner = FakeRunner(CommandResult(0, _SAMPLE_XML, "", 0.3))
        plugin = _make_plugin(runner=runner)
        result = plugin.scan(_TARGET, PluginConfig())
        assert isinstance(result, ScannerResult)
        assert result.scanner_id == ScannerId("nmap")

    def test_empty_output_returns_empty_findings(self) -> None:
        runner = FakeRunner(CommandResult(0, "", "", 0.0))
        plugin = _make_plugin(runner=runner)
        result = plugin.scan(_TARGET, PluginConfig())
        assert result.findings == ()

    def test_build_args_includes_xml_output(self) -> None:
        runner = FakeRunner(CommandResult(0, _SAMPLE_XML, "", 0.1))
        plugin = _make_plugin(runner=runner)
        plugin.scan(_TARGET, PluginConfig())
        args = runner.calls[0][0]
        assert "-oX" in args
        assert "-" in args

    def test_build_args_includes_target(self) -> None:
        runner = FakeRunner(CommandResult(0, _SAMPLE_XML, "", 0.1))
        plugin = _make_plugin(runner=runner)
        plugin.scan(_TARGET, PluginConfig())
        args = runner.calls[0][0]
        assert "10.0.0.5" in args

    def test_build_args_includes_scan_args(self) -> None:
        runner = FakeRunner(CommandResult(0, _SAMPLE_XML, "", 0.1))
        plugin = _make_plugin(runner=runner)
        plugin.scan(_TARGET, PluginConfig())
        args = runner.calls[0][0]
        assert "-sV" in args


# ===========================================================================
# Phase 2B Task 2 Decision 4 - port specification
# ===========================================================================


class TestPortSpecification:
    """Structural guarantee (Requirement 4, second correction): the
    recorded port specification must state what was ACTUALLY scanned and
    must never claim KingSec chose specific default ports when nmap's own
    default sweep was used - the prior version of this class asserted a
    literal KingSec-owned port list here, which stopped being true the
    moment the two-invocation design made that list unused (see
    nmap_default_ports.py's docstring). These tests assert the honest
    description instead.
    """

    def test_phase1_case_url_with_explicit_port(self) -> None:
        """The exact Phase 1 failure by name: http://127.0.0.1:18080 must
        scan 18080, and the spec must say so plainly."""
        runner = FakeRunner(CommandResult(0, _SAMPLE_XML, "", 0.1))
        plugin = _make_plugin(runner=runner)
        target = Target("http://127.0.0.1:18080/", TargetType.URL)
        result = plugin.scan(target, PluginConfig())
        assert result.port_specification is not None
        assert "18080" in result.port_specification

    def test_default_port_recorded_as_nmaps_default_not_a_kingsec_list(self) -> None:
        """Requirement 4: must not imply KingSec chose the ports when
        nmap's own default was used."""
        runner = FakeRunner(CommandResult(0, _SAMPLE_XML, "", 0.1))
        plugin = _make_plugin(runner=runner)
        target = Target("http://example.com/", TargetType.URL)
        result = plugin.scan(target, PluginConfig())
        assert result.port_specification is not None
        assert "nmap" in result.port_specification.lower()
        assert "default" in result.port_specification.lower()

    def test_non_url_target_records_an_explicit_default_sentinel_not_none(self) -> None:
        """Task 4 FIX 1: a non-URL run must RECORD its specification
        explicitly (a sentinel meaning "nmap's own unmodified default"),
        never leave the field absent/None - None must mean "not recorded
        at all" going forward, not "nmap's own default was used"."""
        runner = FakeRunner(CommandResult(0, _SAMPLE_XML, "", 0.1))
        plugin = _make_plugin(runner=runner)
        result = plugin.scan(_TARGET, PluginConfig())
        assert result.port_specification is not None
        assert "nmap" in result.port_specification.lower()
        assert "default" in result.port_specification.lower()

    def test_explicit_port_reaches_the_real_nmap_invocation(self) -> None:
        """Not just recorded - actually present in the -p argument one of
        the two nmap invocations receives, so the recorded spec and the
        real invocation can never silently diverge."""
        runner = FakeRunner(CommandResult(0, _SAMPLE_XML, "", 0.1))
        plugin = _make_plugin(runner=runner)
        target = Target("http://127.0.0.1:18080/", TargetType.URL)
        plugin.scan(target, PluginConfig())
        explicit_calls = [c[0] for c in runner.calls if "-p" in c[0]]
        assert len(explicit_calls) == 1
        args = explicit_calls[0]
        p_idx = args.index("-p")
        assert args[p_idx + 1] == "18080"

    def test_operator_configured_p_flag_does_not_drop_the_url_port(self) -> None:
        """Decision 4d: an operator-configured -p in scan_args must not be
        able to silently drop the URL's explicit port from the explicit
        invocation."""
        runner = FakeRunner(CommandResult(0, _SAMPLE_XML, "", 0.1))
        settings = NmapSettings(scan_args=("-sV", "-n", "-p", "9999"))
        plugin = NmapPlugin(settings, runner=runner)
        target = Target("http://127.0.0.1:18080/", TargetType.URL)
        result = plugin.scan(target, PluginConfig())
        assert result.port_specification is not None
        assert "18080" in result.port_specification
        explicit_calls = [c[0] for c in runner.calls if "-p" in c[0]]
        assert len(explicit_calls) == 1
        args = explicit_calls[0]
        assert args.count("-p") == 1
        p_idx = args.index("-p")
        assert args[p_idx + 1] == "18080"

    def test_operator_configured_p_flag_override_reaches_the_report(self) -> None:
        """The override must not be silent (Decision 4, this round's
        correction): it must reach ScannerResult.warnings, which is what
        survives into the persisted report - not only a log line."""
        runner = FakeRunner(CommandResult(0, _SAMPLE_XML, "", 0.1))
        settings = NmapSettings(scan_args=("-sV", "-n", "-p", "9999"))
        plugin = NmapPlugin(settings, runner=runner)
        target = Target("http://127.0.0.1:18080/", TargetType.URL)
        result = plugin.scan(target, PluginConfig())
        assert len(result.warnings) == 1
        assert "9999" in result.warnings[0]
        assert "ignored" in result.warnings[0].lower()

    def test_no_operator_port_flag_means_no_warning(self) -> None:
        runner = FakeRunner(CommandResult(0, _SAMPLE_XML, "", 0.1))
        plugin = _make_plugin(runner=runner)
        target = Target("http://127.0.0.1:18080/", TargetType.URL)
        result = plugin.scan(target, PluginConfig())
        assert result.warnings == ()


# ===========================================================================
# Phase 2B Task 2 (second correction) - two-invocation URL design
# ===========================================================================


class _BranchingRunner:
    """CommandRunner double that returns a different outcome depending on
    whether the invocation is nmap's default sweep (no -p in args) or the
    explicit-port invocation (-p present) - the two-invocation URL design
    issues both per scan(), and the shared FakeRunner can't tell them
    apart, so failure-semantics tests need a runner that can.
    """

    def __init__(
        self,
        *,
        sweep_result: CommandResult | None = None,
        sweep_exception: Exception | None = None,
        explicit_result: CommandResult | None = None,
        explicit_exception: Exception | None = None,
    ) -> None:
        self._sweep_result = sweep_result
        self._sweep_exception = sweep_exception
        self._explicit_result = explicit_result
        self._explicit_exception = explicit_exception
        self.calls: list[list[str]] = []

    def run(self, args: list[str], *, timeout: float) -> CommandResult:
        self.calls.append(list(args))
        if "-p" in args:
            if self._explicit_exception is not None:
                raise self._explicit_exception
            return self._explicit_result if self._explicit_result is not None else CommandResult(0, "", "", 0.0)
        if self._sweep_exception is not None:
            raise self._sweep_exception
        return self._sweep_result if self._sweep_result is not None else CommandResult(0, "", "", 0.0)


class TestNonUrlTargetsNeverGetAPortFlag:
    """Requirement 1: non-URL targets must be byte-identical to before this
    whole feature existed - a single invocation, no port flag at all. This
    must fail if a port flag is ever reintroduced for these target types,
    e.g. by someone reusing the URL path's port_spec plumbing by mistake.
    """

    @pytest.mark.parametrize(
        "target",
        [
            Target("10.0.0.5", TargetType.IP_ADDRESS),
            Target("example.com", TargetType.HOSTNAME),
            Target("10.0.0.0/24", TargetType.NETWORK),
        ],
        ids=["ip_address", "hostname", "network"],
    )
    def test_no_port_selector_flag_in_args(self, target: Target) -> None:
        runner = FakeRunner(CommandResult(0, _SAMPLE_XML, "", 0.1))
        plugin = _make_plugin(runner=runner)
        plugin.scan(target, PluginConfig())
        args = runner.calls[0][0]
        assert "-p" not in args
        assert "--top-ports" not in args
        assert "-p-" not in args
        assert "-F" not in args

    @pytest.mark.parametrize(
        "target",
        [
            Target("10.0.0.5", TargetType.IP_ADDRESS),
            Target("example.com", TargetType.HOSTNAME),
            Target("10.0.0.0/24", TargetType.NETWORK),
        ],
        ids=["ip_address", "hostname", "network"],
    )
    def test_exactly_one_invocation(self, target: Target) -> None:
        runner = FakeRunner(CommandResult(0, _SAMPLE_XML, "", 0.1))
        plugin = _make_plugin(runner=runner)
        plugin.scan(target, PluginConfig())
        assert len(runner.calls) == 1


class TestUrlTwoInvocationMerge:
    """Requirement 2: URL targets run nmap twice (default sweep, explicit
    port) and the results are merged and deduplicated by port number."""

    def test_two_invocations_issued(self) -> None:
        runner = FakeRunner(CommandResult(0, _SAMPLE_XML, "", 0.1))
        plugin = _make_plugin(runner=runner)
        target = Target("http://127.0.0.1:18080/", TargetType.URL)
        plugin.scan(target, PluginConfig())
        assert len(runner.calls) == 2

    def test_sweep_invocation_has_no_port_flag(self) -> None:
        runner = FakeRunner(CommandResult(0, _SAMPLE_XML, "", 0.1))
        plugin = _make_plugin(runner=runner)
        target = Target("http://127.0.0.1:18080/", TargetType.URL)
        plugin.scan(target, PluginConfig())
        sweep_calls = [c[0] for c in runner.calls if "-p" not in c[0]]
        assert len(sweep_calls) == 1

    def test_explicit_invocation_has_only_the_urls_port(self) -> None:
        runner = FakeRunner(CommandResult(0, _SAMPLE_XML, "", 0.1))
        plugin = _make_plugin(runner=runner)
        target = Target("http://127.0.0.1:18080/", TargetType.URL)
        plugin.scan(target, PluginConfig())
        explicit_calls = [c[0] for c in runner.calls if "-p" in c[0]]
        assert len(explicit_calls) == 1
        p_idx = explicit_calls[0].index("-p")
        assert explicit_calls[0][p_idx + 1] == "18080"

    def test_duplicate_open_port_from_both_invocations_is_deduped(self) -> None:
        # Both invocations return the same canned XML (port 22 open) -
        # the merge must not report it twice.
        runner = _BranchingRunner(
            sweep_result=CommandResult(0, _SAMPLE_XML, "", 0.1),
            explicit_result=CommandResult(0, _SAMPLE_XML, "", 0.1),
        )
        plugin = _make_plugin(runner=runner)
        target = Target("http://127.0.0.1:22/", TargetType.URL)
        result = plugin.scan(target, PluginConfig())
        assert len(result.findings) == 1

    def test_distinct_ports_from_each_invocation_both_survive(self) -> None:
        explicit_xml = _SAMPLE_XML.replace('portid="22"', 'portid="18080"').replace(
            'name="ssh" product="OpenSSH" version="8.2p1"', 'name="http-proxy"'
        )
        runner = _BranchingRunner(
            sweep_result=CommandResult(0, _SAMPLE_XML, "", 0.1),
            explicit_result=CommandResult(0, explicit_xml, "", 0.1),
        )
        plugin = _make_plugin(runner=runner)
        target = Target("http://127.0.0.1:18080/", TargetType.URL)
        result = plugin.scan(target, PluginConfig())
        assert len(result.findings) == 2


class TestUrlTwoInvocationFailureSemantics:
    """Requirement 3: both succeed -> SUCCEEDED, no warning. Both fail ->
    FAILED (ScannerExecutionError). Exactly one fails -> SUCCEEDED with a
    warning naming which sweep failed - never a silent partial result.
    """

    def test_both_succeed_no_warning(self) -> None:
        runner = _BranchingRunner(
            sweep_result=CommandResult(0, _SAMPLE_XML, "", 0.1),
            explicit_result=CommandResult(0, _SAMPLE_XML, "", 0.1),
        )
        plugin = _make_plugin(runner=runner)
        target = Target("http://127.0.0.1:18080/", TargetType.URL)
        result = plugin.scan(target, PluginConfig())
        assert result.warnings == ()

    def test_both_fail_raises_and_run_reaches_failed(self) -> None:
        runner = _BranchingRunner(
            sweep_result=CommandResult(1, "", "boom", 0.1),
            explicit_result=CommandResult(1, "", "boom", 0.1),
        )
        plugin = _make_plugin(runner=runner)
        target = Target("http://127.0.0.1:18080/", TargetType.URL)
        with pytest.raises(ScannerExecutionError):
            plugin.scan(target, PluginConfig())

    def test_sweep_fails_explicit_succeeds_is_succeeded_with_warning(self) -> None:
        runner = _BranchingRunner(
            sweep_exception=ScannerExecutionError("sweep timed out", user_message="timed out"),
            explicit_result=CommandResult(0, _SAMPLE_XML, "", 0.1),
        )
        plugin = _make_plugin(runner=runner)
        target = Target("http://127.0.0.1:18080/", TargetType.URL)
        result = plugin.scan(target, PluginConfig())
        assert len(result.findings) == 1
        assert len(result.warnings) == 1
        assert "default" in result.warnings[0].lower() or "sweep" in result.warnings[0].lower()

    def test_explicit_fails_sweep_succeeds_is_succeeded_with_warning(self) -> None:
        runner = _BranchingRunner(
            sweep_result=CommandResult(0, _SAMPLE_XML, "", 0.1),
            explicit_exception=ScannerExecutionError("explicit port scan failed", user_message="failed"),
        )
        plugin = _make_plugin(runner=runner)
        target = Target("http://127.0.0.1:18080/", TargetType.URL)
        result = plugin.scan(target, PluginConfig())
        assert len(result.findings) == 1
        assert len(result.warnings) == 1
        assert "18080" in result.warnings[0] or "explicit" in result.warnings[0].lower()


# ===========================================================================
# Phase 2B Task 2 Addition 1 - IPv6
# ===========================================================================


class TestIpv6:
    def test_ipv6_ip_address_target_adds_dash_6(self) -> None:
        runner = FakeRunner(CommandResult(0, _SAMPLE_XML, "", 0.1))
        plugin = _make_plugin(runner=runner)
        target = Target("::1", TargetType.IP_ADDRESS)
        plugin.scan(target, PluginConfig())
        args = runner.calls[0][0]
        assert "-6" in args
        assert "::1" in args

    def test_ipv4_ip_address_target_has_no_dash_6(self) -> None:
        runner = FakeRunner(CommandResult(0, _SAMPLE_XML, "", 0.1))
        plugin = _make_plugin(runner=runner)
        plugin.scan(_TARGET, PluginConfig())
        args = runner.calls[0][0]
        assert "-6" not in args


# ===========================================================================
# Provisioning
# ===========================================================================


class TestProvisioning:
    def test_registry_contains_nmap_plugin(self) -> None:
        from kingsec.bootstrap import Container
        from kingsec.infrastructure.config import Settings
        from kingsec.infrastructure.scanner import register_scanner

        container = Container()
        runner = FakeRunner(CommandResult(0, _SAMPLE_XML, "", 0.0))
        register_scanner(container, Settings(), runner=runner)

        from kingsec.application import ScannerPort

        scanner = container.resolve(ScannerPort)
        from kingsec.infrastructure.scanner.orchestrator import ScannerOrchestrator

        assert isinstance(scanner, ScannerOrchestrator)

    def test_orchestrator_resolves_nmap(self) -> None:
        from kingsec.application import ScannerPort
        from kingsec.bootstrap import Container
        from kingsec.infrastructure.config.models import NmapSettings
        from kingsec.infrastructure.scanner.orchestrator import ScannerOrchestrator
        from kingsec.infrastructure.scanner.plugins.nmap import NmapPlugin
        from kingsec.infrastructure.scanner.registry import InMemoryPluginRegistry

        container = Container()
        runner = FakeRunner(CommandResult(0, _SAMPLE_XML, "", 0.0))

        # Register only the Nmap plugin (Nuclei binary not available in tests)
        registry = InMemoryPluginRegistry()
        nmap_plugin = NmapPlugin(NmapSettings(binary_path="python"), runner=runner)
        registry.register(nmap_plugin)

        orchestrator = ScannerOrchestrator(registry)
        container.register_instance(ScannerPort, orchestrator)

        scanner = container.resolve(ScannerPort)
        findings = scanner.scan(_TARGET)
        assert len(findings) == 1
        assert findings[0].severity is Severity.LOW
