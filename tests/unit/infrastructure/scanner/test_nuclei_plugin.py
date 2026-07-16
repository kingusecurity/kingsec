"""NucleiPlugin: metadata, capabilities, availability, scan delegation, and provisioning."""

from __future__ import annotations

from pathlib import Path
from unittest.mock import MagicMock

import pytest

from kingsec.application.ports.scanner_plugin import ScannerPluginPort
from kingsec.domain import (
    Finding,
    PluginAvailability,
    PluginConfig,
    ScannerId,
    ScannerResult,
    Severity,
    Target,
    TargetType,
)
from kingsec.infrastructure.config.models import ScannerSettings
from kingsec.infrastructure.scanner.errors import ScannerExecutionError
from kingsec.infrastructure.scanner.plugins.nuclei import NucleiPlugin
from kingsec.infrastructure.scanner.runner import CommandResult
from tests.unit.infrastructure.scanner.conftest import FakeRunner

_TARGET = Target("10.0.0.5", TargetType.IP_ADDRESS)
_SAMPLE = (
    '{"template-id":"t1","info":{"name":"Crit","severity":"critical"},'
    '"matched-at":"http://10.0.0.5/x"}'
)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _make_plugin(
    *,
    binary_path: str = "nuclei",
    runner: FakeRunner | None = None,
) -> NucleiPlugin:
    settings = ScannerSettings(binary_path=binary_path)
    return NucleiPlugin(settings, runner=runner)


# ===========================================================================
# Metadata
# ===========================================================================


class TestMetadata:
    def test_plugin_id(self) -> None:
        plugin = _make_plugin()
        assert plugin.metadata().id == ScannerId("nuclei")

    def test_plugin_name(self) -> None:
        assert _make_plugin().metadata().name == "Nuclei Scanner"

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
        assert TargetType.IP_ADDRESS in target_types
        assert TargetType.HOSTNAME in target_types
        assert TargetType.URL in target_types

    def test_vulnerability_category(self) -> None:
        from kingsec.domain import ScanCategory
        caps = _make_plugin().capabilities()
        assert ScanCategory.VULNERABILITY in caps[0].scan_categories

    def test_structured_json_output(self) -> None:
        from kingsec.domain import OutputFormat
        caps = _make_plugin().capabilities()
        assert caps[0].output_format is OutputFormat.STRUCTURED_JSON


# ===========================================================================
# Availability
# ===========================================================================


class TestAvailability:
    def test_available_when_binary_found(self) -> None:
        plugin = _make_plugin(binary_path="python")  # python is always in PATH
        avail = plugin.is_available()
        assert avail.available is True
        assert avail.reason is None

    def test_unavailable_when_binary_missing(self) -> None:
        plugin = _make_plugin(binary_path="definitely-not-a-real-binary-xyz")
        avail = plugin.is_available()
        assert avail.available is False
        assert avail.reason is not None
        assert "definitely-not-a-real-binary-xyz" in avail.reason


# ===========================================================================
# Scan delegation
# ===========================================================================


class TestScan:
    def test_delegates_to_adapter(self) -> None:
        runner = FakeRunner(CommandResult(0, _SAMPLE, "", 0.5))
        plugin = _make_plugin(runner=runner)
        result = plugin.scan(_TARGET, PluginConfig())
        assert isinstance(result, ScannerResult)
        assert result.scanner_id == ScannerId("nuclei")
        assert len(result.findings) == 1
        assert result.findings[0].severity is Severity.CRITICAL

    def test_adapter_exceptions_propagated(self) -> None:
        runner = FakeRunner(CommandResult(2, "", "fatal", 0.1))
        plugin = _make_plugin(runner=runner)
        with pytest.raises(ScannerExecutionError):
            plugin.scan(_TARGET, PluginConfig())

    def test_scanner_result_returned_unchanged(self) -> None:
        runner = FakeRunner(CommandResult(0, _SAMPLE, "", 0.3))
        plugin = _make_plugin(runner=runner)
        result = plugin.scan(_TARGET, PluginConfig())
        assert isinstance(result, ScannerResult)
        assert result.scanner_id == ScannerId("nuclei")

    def test_empty_output_returns_empty_findings(self) -> None:
        runner = FakeRunner(CommandResult(0, "", "", 0.0))
        plugin = _make_plugin(runner=runner)
        result = plugin.scan(_TARGET, PluginConfig())
        assert result.findings == ()


# ===========================================================================
# Provisioning
# ===========================================================================


class TestProvisioning:
    def test_registry_contains_nuclei_plugin(self) -> None:
        from kingsec.infrastructure.config import Settings
        from kingsec.infrastructure.scanner import register_scanner
        from kingsec.bootstrap import Container

        container = Container()
        runner = FakeRunner(CommandResult(0, _SAMPLE, "", 0.0))
        register_scanner(container, Settings(), runner=runner)

        from kingsec.application import ScannerPort
        scanner = container.resolve(ScannerPort)
        # The scanner is now an orchestrator wrapping the NucleiPlugin
        from kingsec.infrastructure.scanner.orchestrator import ScannerOrchestrator
        assert isinstance(scanner, ScannerOrchestrator)

    def test_orchestrator_resolves_nuclei(self) -> None:
        from kingsec.infrastructure.config import Settings
        from kingsec.infrastructure.config.models import ScannerSettings
        from kingsec.infrastructure.scanner import register_scanner
        from kingsec.bootstrap import Container

        container = Container()
        runner = FakeRunner(CommandResult(0, _SAMPLE, "", 0.0))
        settings = Settings()
        # Override the scanner sub-settings with a binary that exists
        scanner_settings = ScannerSettings(binary_path="python")
        settings = settings.model_copy(update={"scanner": scanner_settings})
        register_scanner(container, settings, runner=runner)

        from kingsec.application import ScannerPort
        scanner = container.resolve(ScannerPort)
        findings = scanner.scan(_TARGET)
        assert len(findings) == 1
        assert findings[0].severity is Severity.CRITICAL
