"""NiktoPlugin: metadata, capabilities, availability, scan delegation, and provisioning."""

from __future__ import annotations

import pytest

from kingsec.application.ports.scanner_plugin import ScannerPluginPort
from kingsec.domain import (
    PluginConfig,
    ScanCategory,
    ScannerId,
    ScannerResult,
    Target,
    TargetType,
)
from kingsec.infrastructure.config.models import NiktoSettings
from kingsec.infrastructure.scanner.errors import BINARY_ABSENT_USER_MESSAGE, ScannerExecutionError
from kingsec.infrastructure.scanner.plugins.nikto import NiktoPlugin
from kingsec.infrastructure.scanner.runner import CommandResult
from tests.unit.infrastructure.scanner.conftest import FakeRunner

_TARGET = Target("example.com", TargetType.HOSTNAME)

_SAMPLE_OUTPUT = """\
- Nikto v2.5.0
---------------------------------------------------------------------------
+ Target IP:           10.0.0.5
+ Target Hostname:     example.com
+ Target Port:         80
+ Start Time: 2024-01-01 12:00:00
---------------------------------------------------------------------------
+ Server: Apache/2.4.41
+ /: The anti-clickjacking X-Frame-Options header is not present.
+ /: Directory indexing found.
+ /admin/: Admin directory found.
+ OSVDB-3092: /admin/: Admin directory found.
+ /: Cookie without HttpOnly flag set.
---------------------------------------------------------------------------
+ End Time:            2024-01-01 12:01:00
---------------------------------------------------------------------------
1 host(s) tested
"""


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _make_plugin(
    *,
    binary_path: str = "nikto",
    runner: FakeRunner | None = None,
) -> NiktoPlugin:
    settings = NiktoSettings(binary_path=binary_path)
    return NiktoPlugin(settings, runner=runner)


# ===========================================================================
# Metadata
# ===========================================================================


class TestMetadata:
    def test_plugin_id(self) -> None:
        assert _make_plugin().metadata().id == ScannerId("nikto")

    def test_plugin_name(self) -> None:
        assert _make_plugin().metadata().name == "Nikto Scanner"

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
    def test_correct_target_types(self) -> None:
        caps = _make_plugin().capabilities()
        assert len(caps) == 1
        target_types = caps[0].target_types
        assert TargetType.HOSTNAME in target_types
        assert TargetType.URL in target_types
        assert TargetType.IP_ADDRESS not in target_types

    def test_vulnerability_category(self) -> None:
        caps = _make_plugin().capabilities()
        assert ScanCategory.VULNERABILITY in caps[0].scan_categories

    def test_no_discovery_category(self) -> None:
        caps = _make_plugin().capabilities()
        assert ScanCategory.DISCOVERY not in caps[0].scan_categories

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
        plugin = _make_plugin(binary_path="definitely-not-nikto-xyz")
        avail = plugin.is_available()
        assert avail.available is False
        assert avail.reason is not None
        # Phase 08: deliberately replaced, not weakened - see nmap's
        # equivalent test for the full reasoning.
        assert "definitely-not-nikto-xyz" not in avail.reason
        assert avail.reason == BINARY_ABSENT_USER_MESSAGE


# ===========================================================================
# Scan delegation
# ===========================================================================


class TestScan:
    def test_delegates_to_adapter(self) -> None:
        runner = FakeRunner(CommandResult(0, _SAMPLE_OUTPUT, "", 0.5))
        plugin = _make_plugin(runner=runner)
        result = plugin.scan(_TARGET, PluginConfig())
        assert isinstance(result, ScannerResult)
        assert result.scanner_id == ScannerId("nikto")
        assert len(result.findings) == 6

    def test_adapter_exceptions_propagated(self) -> None:
        runner = FakeRunner(CommandResult(1, "", "error", 0.1))
        plugin = _make_plugin(runner=runner)
        with pytest.raises(ScannerExecutionError):
            plugin.scan(_TARGET, PluginConfig())

    def test_scanner_result_returned_unchanged(self) -> None:
        runner = FakeRunner(CommandResult(0, _SAMPLE_OUTPUT, "", 0.3))
        plugin = _make_plugin(runner=runner)
        result = plugin.scan(_TARGET, PluginConfig())
        assert isinstance(result, ScannerResult)
        assert result.scanner_id == ScannerId("nikto")

    def test_empty_output_returns_empty_findings(self) -> None:
        runner = FakeRunner(CommandResult(0, "", "", 0.0))
        plugin = _make_plugin(runner=runner)
        result = plugin.scan(_TARGET, PluginConfig())
        assert result.findings == ()

    def test_build_args_includes_h_flag(self) -> None:
        runner = FakeRunner(CommandResult(0, _SAMPLE_OUTPUT, "", 0.1))
        plugin = _make_plugin(runner=runner)
        plugin.scan(_TARGET, PluginConfig())
        args = runner.calls[0][0]
        assert "-h" in args

    def test_build_args_includes_target(self) -> None:
        runner = FakeRunner(CommandResult(0, _SAMPLE_OUTPUT, "", 0.1))
        plugin = _make_plugin(runner=runner)
        plugin.scan(_TARGET, PluginConfig())
        args = runner.calls[0][0]
        assert "example.com" in args

    def test_build_args_includes_scan_args(self) -> None:
        runner = FakeRunner(CommandResult(0, _SAMPLE_OUTPUT, "", 0.1))
        plugin = _make_plugin(runner=runner)
        plugin.scan(_TARGET, PluginConfig())
        args = runner.calls[0][0]
        assert "-nointeractive" in args


# ===========================================================================
# Provisioning
# ===========================================================================


class TestProvisioning:
    def test_registry_contains_nikto_plugin(self) -> None:
        from kingsec.bootstrap import Container
        from kingsec.infrastructure.config import Settings
        from kingsec.infrastructure.scanner import register_scanner

        container = Container()
        runner = FakeRunner(CommandResult(0, _SAMPLE_OUTPUT, "", 0.0))
        register_scanner(container, Settings(), runner=runner)

        from kingsec.application import ScannerPort

        scanner = container.resolve(ScannerPort)
        from kingsec.infrastructure.scanner.orchestrator import ScannerOrchestrator

        assert isinstance(scanner, ScannerOrchestrator)

    def test_orchestrator_resolves_nikto(self) -> None:
        from kingsec.application import ScannerPort
        from kingsec.bootstrap import Container
        from kingsec.infrastructure.config.models import NiktoSettings
        from kingsec.infrastructure.scanner.orchestrator import ScannerOrchestrator
        from kingsec.infrastructure.scanner.plugins.nikto import NiktoPlugin
        from kingsec.infrastructure.scanner.registry import InMemoryPluginRegistry

        container = Container()
        runner = FakeRunner(CommandResult(0, _SAMPLE_OUTPUT, "", 0.0))

        # Register only the Nikto plugin (Nuclei/Nmap binaries not available)
        registry = InMemoryPluginRegistry()
        nikto_plugin = NiktoPlugin(NiktoSettings(binary_path="python"), runner=runner)
        registry.register(nikto_plugin)

        orchestrator = ScannerOrchestrator(registry)
        container.register_instance(ScannerPort, orchestrator)

        scanner = container.resolve(ScannerPort)
        findings = scanner.scan(_TARGET)
        assert len(findings) == 6
