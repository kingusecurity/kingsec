"""GobusterPlugin: metadata, capabilities, availability, scan delegation, and provisioning."""

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
from kingsec.infrastructure.config.models import GobusterSettings
from kingsec.infrastructure.scanner.errors import ScannerExecutionError
from kingsec.infrastructure.scanner.plugins.gobuster import GobusterPlugin
from kingsec.infrastructure.scanner.runner import CommandResult
from tests.unit.infrastructure.scanner.conftest import FakeRunner

_TARGET = Target("example.com", TargetType.HOSTNAME)

_SAMPLE_OUTPUT = """\
/admin                 (Status: 200) [Size: 1234]
/.git                  (Status: 200) [Size: 567]
/login                 (Status: 301) [Size: 0]
"""


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _make_plugin(
    *,
    binary_path: str = "gobuster",
    wordlist: str = "/usr/share/wordlists/common.txt",
    runner: FakeRunner | None = None,
) -> GobusterPlugin:
    settings = GobusterSettings(binary_path=binary_path, wordlist=wordlist)
    return GobusterPlugin(settings, runner=runner)


# ===========================================================================
# Metadata
# ===========================================================================


class TestMetadata:
    def test_plugin_id(self) -> None:
        assert _make_plugin().metadata().id == ScannerId("gobuster")

    def test_plugin_name(self) -> None:
        assert _make_plugin().metadata().name == "Gobuster Scanner"

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

    def test_discovery_category(self) -> None:
        caps = _make_plugin().capabilities()
        assert ScanCategory.DISCOVERY in caps[0].scan_categories

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
        plugin = _make_plugin(binary_path="definitely-not-gobuster-xyz")
        avail = plugin.is_available()
        assert avail.available is False
        assert avail.reason is not None
        assert "definitely-not-gobuster-xyz" in avail.reason


# ===========================================================================
# Scan delegation
# ===========================================================================


class TestScan:
    def test_delegates_to_adapter(self) -> None:
        runner = FakeRunner(CommandResult(0, _SAMPLE_OUTPUT, "", 0.5))
        plugin = _make_plugin(runner=runner)
        result = plugin.scan(_TARGET, PluginConfig())
        assert isinstance(result, ScannerResult)
        assert result.scanner_id == ScannerId("gobuster")
        assert len(result.findings) == 3

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
        assert result.scanner_id == ScannerId("gobuster")

    def test_empty_output_returns_empty_findings(self) -> None:
        runner = FakeRunner(CommandResult(0, "", "", 0.0))
        plugin = _make_plugin(runner=runner)
        result = plugin.scan(_TARGET, PluginConfig())
        assert result.findings == ()

    def test_build_args_includes_dir_subcommand(self) -> None:
        runner = FakeRunner(CommandResult(0, _SAMPLE_OUTPUT, "", 0.1))
        plugin = _make_plugin(runner=runner)
        plugin.scan(_TARGET, PluginConfig())
        args = runner.calls[0][0]
        assert "dir" in args

    def test_build_args_includes_u_flag(self) -> None:
        runner = FakeRunner(CommandResult(0, _SAMPLE_OUTPUT, "", 0.1))
        plugin = _make_plugin(runner=runner)
        plugin.scan(_TARGET, PluginConfig())
        args = runner.calls[0][0]
        assert "-u" in args

    def test_build_args_includes_target(self) -> None:
        runner = FakeRunner(CommandResult(0, _SAMPLE_OUTPUT, "", 0.1))
        plugin = _make_plugin(runner=runner)
        plugin.scan(_TARGET, PluginConfig())
        args = runner.calls[0][0]
        u_idx = args.index("-u")
        assert args[u_idx + 1] == "example.com"

    def test_build_args_includes_wordlist(self) -> None:
        runner = FakeRunner(CommandResult(0, _SAMPLE_OUTPUT, "", 0.1))
        plugin = _make_plugin(runner=runner)
        plugin.scan(_TARGET, PluginConfig())
        args = runner.calls[0][0]
        assert "-w" in args
        w_idx = args.index("-w")
        assert "common.txt" in args[w_idx + 1]


# ===========================================================================
# Provisioning
# ===========================================================================


class TestProvisioning:
    def test_registry_contains_gobuster_plugin(self) -> None:
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

    def test_orchestrator_resolves_gobuster(self) -> None:
        from kingsec.application import ScannerPort
        from kingsec.bootstrap import Container
        from kingsec.infrastructure.scanner.orchestrator import ScannerOrchestrator
        from kingsec.infrastructure.scanner.plugins.gobuster import GobusterPlugin
        from kingsec.infrastructure.scanner.registry import InMemoryPluginRegistry

        container = Container()
        runner = FakeRunner(CommandResult(0, _SAMPLE_OUTPUT, "", 0.0))

        # Register only the gobuster plugin (other binaries not available)
        registry = InMemoryPluginRegistry()
        gobuster_plugin = GobusterPlugin(
            GobusterSettings(binary_path="python", wordlist="/tmp/wl.txt"),
            runner=runner,
        )
        registry.register(gobuster_plugin)

        orchestrator = ScannerOrchestrator(registry)
        container.register_instance(ScannerPort, orchestrator)

        scanner = container.resolve(ScannerPort)
        findings = scanner.scan(_TARGET)
        assert len(findings) == 3
