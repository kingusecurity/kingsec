"""TrivyPlugin: metadata, capabilities, availability, scan delegation, and provisioning."""

from __future__ import annotations

import json

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
from kingsec.infrastructure.config.models import TrivySettings
from kingsec.infrastructure.scanner.errors import ScannerExecutionError
from kingsec.infrastructure.scanner.plugins.trivy import TrivyPlugin
from kingsec.infrastructure.scanner.runner import CommandResult
from tests.unit.infrastructure.scanner.conftest import FakeRunner

_TARGET = Target("example.com", TargetType.HOSTNAME)

_SAMPLE_JSONL = json.dumps(
    {
        "Results": [
            {
                "Target": "/app",
                "Class": "lang-pkgs",
                "Vulnerabilities": [
                    {
                        "VulnerabilityID": "CVE-2024-1234",
                        "PkgName": "openssl",
                        "InstalledVersion": "1.1.1",
                        "FixedVersion": "1.1.2",
                        "Severity": "HIGH",
                        "Title": "OpenSSL Vulnerability",
                        "Description": "A vulnerability in OpenSSL",
                    },
                    {
                        "VulnerabilityID": "CVE-2024-9999",
                        "PkgName": "log4j",
                        "InstalledVersion": "2.14.0",
                        "FixedVersion": "2.17.0",
                        "Severity": "CRITICAL",
                        "Title": "Log4Shell",
                        "Description": "Remote code execution",
                    },
                ],
            },
            {
                "Target": "/app/config.yaml",
                "Class": "config",
                "Misconfigurations": [
                    {
                        "ID": "DS002",
                        "Severity": "MEDIUM",
                        "Title": "SSH Config",
                        "Message": "SSH protocol 1 enabled",
                        "Resolution": "Disable protocol 1",
                    },
                ],
            },
        ]
    }
)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _make_plugin(
    *,
    binary_path: str = "trivy",
    scan_type: str = "fs",
    runner: FakeRunner | None = None,
) -> TrivyPlugin:
    settings = TrivySettings(binary_path=binary_path, scan_type=scan_type)
    return TrivyPlugin(settings, runner=runner)


# ===========================================================================
# Metadata
# ===========================================================================


class TestMetadata:
    def test_plugin_id(self) -> None:
        assert _make_plugin().metadata().id == ScannerId("trivy")

    def test_plugin_name(self) -> None:
        assert _make_plugin().metadata().name == "Trivy Scanner"

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
        assert TargetType.IP_ADDRESS not in target_types
        assert TargetType.URL not in target_types

    def test_vulnerability_category(self) -> None:
        caps = _make_plugin().capabilities()
        assert ScanCategory.VULNERABILITY in caps[0].scan_categories

    def test_configuration_category(self) -> None:
        caps = _make_plugin().capabilities()
        assert ScanCategory.CONFIGURATION in caps[0].scan_categories

    def test_structured_json_output(self) -> None:
        from kingsec.domain import OutputFormat

        caps = _make_plugin().capabilities()
        assert caps[0].output_format is OutputFormat.STRUCTURED_JSON


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
        plugin = _make_plugin(binary_path="definitely-not-trivy-xyz")
        avail = plugin.is_available()
        assert avail.available is False
        assert avail.reason is not None
        assert "definitely-not-trivy-xyz" in avail.reason


# ===========================================================================
# Scan delegation
# ===========================================================================


class TestScan:
    def test_delegates_to_adapter(self) -> None:
        runner = FakeRunner(CommandResult(0, _SAMPLE_JSONL, "", 0.5))
        plugin = _make_plugin(runner=runner)
        result = plugin.scan(_TARGET, PluginConfig())
        assert isinstance(result, ScannerResult)
        assert result.scanner_id == ScannerId("trivy")
        assert len(result.findings) == 3

    def test_adapter_exceptions_propagated(self) -> None:
        runner = FakeRunner(CommandResult(1, "", "error", 0.1))
        plugin = _make_plugin(runner=runner)
        with pytest.raises(ScannerExecutionError):
            plugin.scan(_TARGET, PluginConfig())

    def test_scanner_result_returned_unchanged(self) -> None:
        runner = FakeRunner(CommandResult(0, _SAMPLE_JSONL, "", 0.3))
        plugin = _make_plugin(runner=runner)
        result = plugin.scan(_TARGET, PluginConfig())
        assert isinstance(result, ScannerResult)
        assert result.scanner_id == ScannerId("trivy")

    def test_empty_output_returns_empty_findings(self) -> None:
        runner = FakeRunner(CommandResult(0, "", "", 0.0))
        plugin = _make_plugin(runner=runner)
        result = plugin.scan(_TARGET, PluginConfig())
        assert result.findings == ()

    def test_build_args_includes_fs_subcommand(self) -> None:
        runner = FakeRunner(CommandResult(0, _SAMPLE_JSONL, "", 0.1))
        plugin = _make_plugin(runner=runner)
        plugin.scan(_TARGET, PluginConfig())
        args = runner.calls[0][0]
        assert "fs" in args

    def test_build_args_includes_image_subcommand(self) -> None:
        runner = FakeRunner(CommandResult(0, _SAMPLE_JSONL, "", 0.1))
        plugin = _make_plugin(scan_type="image", runner=runner)
        plugin.scan(_TARGET, PluginConfig())
        args = runner.calls[0][0]
        assert "image" in args

    def test_build_args_includes_format_json(self) -> None:
        runner = FakeRunner(CommandResult(0, _SAMPLE_JSONL, "", 0.1))
        plugin = _make_plugin(runner=runner)
        plugin.scan(_TARGET, PluginConfig())
        args = runner.calls[0][0]
        assert "--format" in args
        fmt_idx = args.index("--format")
        assert args[fmt_idx + 1] == "json"

    def test_build_args_includes_target(self) -> None:
        runner = FakeRunner(CommandResult(0, _SAMPLE_JSONL, "", 0.1))
        plugin = _make_plugin(runner=runner)
        plugin.scan(_TARGET, PluginConfig())
        args = runner.calls[0][0]
        assert "example.com" in args


# ===========================================================================
# Provisioning
# ===========================================================================


class TestProvisioning:
    def test_registry_contains_trivy_plugin(self) -> None:
        from kingsec.bootstrap import Container
        from kingsec.infrastructure.config import Settings
        from kingsec.infrastructure.scanner import register_scanner

        container = Container()
        runner = FakeRunner(CommandResult(0, _SAMPLE_JSONL, "", 0.0))
        register_scanner(container, Settings(), runner=runner)

        from kingsec.application import ScannerPort

        scanner = container.resolve(ScannerPort)
        from kingsec.infrastructure.scanner.orchestrator import ScannerOrchestrator

        assert isinstance(scanner, ScannerOrchestrator)

    def test_orchestrator_resolves_trivy(self) -> None:
        from kingsec.application import ScannerPort
        from kingsec.bootstrap import Container
        from kingsec.infrastructure.scanner.orchestrator import ScannerOrchestrator
        from kingsec.infrastructure.scanner.plugins.trivy import TrivyPlugin
        from kingsec.infrastructure.scanner.registry import InMemoryPluginRegistry

        container = Container()
        runner = FakeRunner(CommandResult(0, _SAMPLE_JSONL, "", 0.0))

        # Register only the trivy plugin
        registry = InMemoryPluginRegistry()
        trivy_plugin = TrivyPlugin(
            TrivySettings(binary_path="python"),
            runner=runner,
        )
        registry.register(trivy_plugin)

        orchestrator = ScannerOrchestrator(registry)
        container.register_instance(ScannerPort, orchestrator)

        scanner = container.resolve(ScannerPort)
        findings = scanner.scan(_TARGET)
        assert len(findings) == 3
