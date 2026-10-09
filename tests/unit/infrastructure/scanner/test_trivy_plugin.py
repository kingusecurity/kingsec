"""TrivyPlugin: metadata, capabilities, availability, scan delegation, and provisioning."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from kingsec.application.ports.scanner_plugin import ScannerPluginPort
from kingsec.domain import (
    PluginConfig,
    ScanCategory,
    ScannerId,
    ScannerRequirement,
    ScannerResult,
    Target,
    TargetType,
)
from kingsec.infrastructure.config.models import TrivySettings
from kingsec.infrastructure.scanner.errors import (
    BINARY_ABSENT_USER_MESSAGE,
    ScannerExecutionError,
    ScannerOutputError,
)
from kingsec.infrastructure.scanner.plugins.trivy import TrivyPlugin
from kingsec.infrastructure.scanner.runner import CommandResult
from tests.unit.infrastructure.scanner.conftest import FakeRunner

_SOURCE_TARGET = Target(str(Path(__file__).resolve().parent), TargetType.SOURCE_PATH)
_IMAGE_TARGET = Target("alpine:3.20", TargetType.CONTAINER_IMAGE)

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
    def test_declares_source_path_and_container_image(self) -> None:
        caps = _make_plugin().capabilities()
        assert len(caps) == 2
        assert {cap.requirement for cap in caps} == {
            ScannerRequirement.SOURCE_PATH,
            ScannerRequirement.CONTAINER_IMAGE,
        }

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
        # Phase 08: deliberately replaced, not weakened - see nmap's
        # equivalent test for the full reasoning.
        assert "definitely-not-trivy-xyz" not in avail.reason
        assert avail.reason == BINARY_ABSENT_USER_MESSAGE


# ===========================================================================
# Scan delegation
# ===========================================================================


class TestScan:
    def test_delegates_to_adapter(self) -> None:
        runner = FakeRunner(CommandResult(0, _SAMPLE_JSONL, "", 0.5))
        plugin = _make_plugin(runner=runner)
        result = plugin.scan(_SOURCE_TARGET, PluginConfig())
        assert isinstance(result, ScannerResult)
        assert result.scanner_id == ScannerId("trivy")
        assert len(result.findings) == 3

    def test_adapter_exceptions_propagated(self) -> None:
        runner = FakeRunner(CommandResult(1, "", "error", 0.1))
        plugin = _make_plugin(runner=runner)
        with pytest.raises(ScannerExecutionError):
            plugin.scan(_SOURCE_TARGET, PluginConfig())

    def test_scanner_result_returned_unchanged(self) -> None:
        runner = FakeRunner(CommandResult(0, _SAMPLE_JSONL, "", 0.3))
        plugin = _make_plugin(runner=runner)
        result = plugin.scan(_SOURCE_TARGET, PluginConfig())
        assert isinstance(result, ScannerResult)
        assert result.scanner_id == ScannerId("trivy")

    def test_empty_output_raises_output_error(self) -> None:
        runner = FakeRunner(CommandResult(0, "", "", 0.0))
        plugin = _make_plugin(runner=runner)
        with pytest.raises(ScannerOutputError):
            plugin.scan(_SOURCE_TARGET, PluginConfig())

    def test_valid_empty_report_returns_empty_findings(self) -> None:
        runner = FakeRunner(CommandResult(0, json.dumps({"Results": []}), "", 0.0))
        plugin = _make_plugin(runner=runner)
        result = plugin.scan(_SOURCE_TARGET, PluginConfig())
        assert result.findings == ()

    def test_malformed_nonempty_output_raises_output_error(self) -> None:
        runner = FakeRunner(CommandResult(0, "not trivy json", "", 0.0))
        plugin = _make_plugin(runner=runner)
        with pytest.raises(ScannerOutputError):
            plugin.scan(_SOURCE_TARGET, PluginConfig())

    def test_missing_source_path_fails_before_execution(self, tmp_path: Path) -> None:
        target = Target(str(tmp_path / "missing"), TargetType.SOURCE_PATH)
        runner = FakeRunner(CommandResult(0, _SAMPLE_JSONL, "", 0.1))
        plugin = _make_plugin(runner=runner)

        with pytest.raises(ScannerExecutionError) as exc_info:
            plugin.scan(target, PluginConfig())

        assert runner.calls == []
        assert "exists" in exc_info.value.user_message
        assert target.value not in exc_info.value.user_message

    def test_unreadable_source_path_fails_before_execution(self, monkeypatch: pytest.MonkeyPatch) -> None:
        runner = FakeRunner(CommandResult(0, _SAMPLE_JSONL, "", 0.1))
        plugin = _make_plugin(runner=runner)
        monkeypatch.setattr("kingsec.infrastructure.scanner.trivy.os.access", lambda *_args: False)

        with pytest.raises(ScannerExecutionError) as exc_info:
            plugin.scan(_SOURCE_TARGET, PluginConfig())

        assert runner.calls == []
        assert "readable" in exc_info.value.user_message
        assert _SOURCE_TARGET.value not in exc_info.value.user_message

    def test_source_target_selects_fs_even_when_setting_requests_image(self) -> None:
        runner = FakeRunner(CommandResult(0, _SAMPLE_JSONL, "", 0.1))
        plugin = _make_plugin(scan_type="image", runner=runner)
        plugin.scan(_SOURCE_TARGET, PluginConfig())
        args = runner.calls[0][0]
        assert args[1] == "fs"

    def test_container_image_target_selects_image_even_when_setting_requests_fs(self) -> None:
        runner = FakeRunner(CommandResult(0, _SAMPLE_JSONL, "", 0.1))
        plugin = _make_plugin(scan_type="fs", runner=runner)
        plugin.scan(_IMAGE_TARGET, PluginConfig())
        args = runner.calls[0][0]
        assert args[1] == "image"

    def test_build_args_includes_format_json(self) -> None:
        runner = FakeRunner(CommandResult(0, _SAMPLE_JSONL, "", 0.1))
        plugin = _make_plugin(runner=runner)
        plugin.scan(_SOURCE_TARGET, PluginConfig())
        args = runner.calls[0][0]
        assert "--format" in args
        fmt_idx = args.index("--format")
        assert args[fmt_idx + 1] == "json"

    def test_build_args_includes_target(self) -> None:
        runner = FakeRunner(CommandResult(0, _SAMPLE_JSONL, "", 0.1))
        plugin = _make_plugin(runner=runner)
        plugin.scan(_SOURCE_TARGET, PluginConfig())
        args = runner.calls[0][0]
        assert _SOURCE_TARGET.value in args


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
        findings = scanner.scan(_SOURCE_TARGET)
        assert len(findings) == 3
