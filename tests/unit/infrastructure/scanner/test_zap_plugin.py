"""ZapPlugin: metadata, capabilities, availability, scan delegation, and provisioning."""

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
from kingsec.infrastructure.config.models import ZapSettings
from kingsec.infrastructure.scanner.errors import BINARY_ABSENT_USER_MESSAGE, ScannerExecutionError
from kingsec.infrastructure.scanner.plugins.zap import ZapPlugin
from kingsec.infrastructure.scanner.runner import CommandResult
from tests.unit.infrastructure.scanner.conftest import FakeRunner

_TARGET = Target("http://example.com", TargetType.URL)

_SAMPLE_JSONL = json.dumps(
    {
        "site": [
            {
                "@name": "http://example.com",
                "host": "example.com",
                "alerts": [
                    {
                        "alert": "SQL Injection",
                        "riskcode": "3",
                        "confidence": "High",
                        "description": "SQL injection found",
                        "solution": "Use parameterized queries",
                        "reference": "https://owasp.org",
                        "url": "http://example.com/login",
                        "param": "username",
                    },
                    {
                        "alert": "XSS",
                        "riskcode": "2",
                        "confidence": "Medium",
                        "description": "XSS found",
                        "solution": "Encode output",
                        "reference": "",
                        "url": "http://example.com/search",
                        "param": "q",
                    },
                    {
                        "alert": "Missing Header",
                        "riskcode": "1",
                        "confidence": "Medium",
                        "description": "Header missing",
                        "solution": "Add header",
                        "reference": "",
                        "url": "http://example.com/",
                        "param": "",
                    },
                ],
            }
        ]
    }
)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _make_plugin(
    *,
    binary_path: str = "zap",
    runner: FakeRunner | None = None,
) -> ZapPlugin:
    settings = ZapSettings(binary_path=binary_path)
    return ZapPlugin(settings, runner=runner)


# ===========================================================================
# Metadata
# ===========================================================================


class TestMetadata:
    def test_plugin_id(self) -> None:
        assert _make_plugin().metadata().id == ScannerId("zap")

    def test_plugin_name(self) -> None:
        assert _make_plugin().metadata().name == "OWASP ZAP"

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
        assert TargetType.URL in target_types
        assert TargetType.HOSTNAME not in target_types
        assert TargetType.IP_ADDRESS not in target_types

    def test_vulnerability_category(self) -> None:
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
        plugin = _make_plugin(binary_path="python")
        avail = plugin.is_available()
        assert avail.available is True
        assert avail.reason is None

    def test_unavailable_when_binary_missing(self) -> None:
        plugin = _make_plugin(binary_path="definitely-not-zap-xyz")
        avail = plugin.is_available()
        assert avail.available is False
        assert avail.reason is not None
        # Phase 08: deliberately replaced, not weakened - see nmap's
        # equivalent test for the full reasoning.
        assert "definitely-not-zap-xyz" not in avail.reason
        assert avail.reason == BINARY_ABSENT_USER_MESSAGE


# ===========================================================================
# Scan delegation
# ===========================================================================


class TestScan:
    def test_delegates_to_adapter(self) -> None:
        runner = FakeRunner(CommandResult(0, _SAMPLE_JSONL, "", 0.5))
        plugin = _make_plugin(runner=runner)
        result = plugin.scan(_TARGET, PluginConfig())
        assert isinstance(result, ScannerResult)
        assert result.scanner_id == ScannerId("zap")
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
        assert result.scanner_id == ScannerId("zap")

    def test_empty_output_returns_empty_findings(self) -> None:
        runner = FakeRunner(CommandResult(0, "", "", 0.0))
        plugin = _make_plugin(runner=runner)
        result = plugin.scan(_TARGET, PluginConfig())
        assert result.findings == ()

    def test_build_args_includes_quickurl(self) -> None:
        runner = FakeRunner(CommandResult(0, _SAMPLE_JSONL, "", 0.1))
        plugin = _make_plugin(runner=runner)
        plugin.scan(_TARGET, PluginConfig())
        args = runner.calls[0][0]
        assert "-quickurl" in args

    def test_build_args_includes_target(self) -> None:
        runner = FakeRunner(CommandResult(0, _SAMPLE_JSONL, "", 0.1))
        plugin = _make_plugin(runner=runner)
        plugin.scan(_TARGET, PluginConfig())
        args = runner.calls[0][0]
        url_idx = args.index("-quickurl")
        assert args[url_idx + 1] == "http://example.com"

    def test_build_args_includes_quickout_json(self) -> None:
        runner = FakeRunner(CommandResult(0, _SAMPLE_JSONL, "", 0.1))
        plugin = _make_plugin(runner=runner)
        plugin.scan(_TARGET, PluginConfig())
        args = runner.calls[0][0]
        assert "-quickout" in args
        out_idx = args.index("-quickout")
        assert args[out_idx + 1] == "json"


# ===========================================================================
# Provisioning
# ===========================================================================


class TestProvisioning:
    def test_registry_contains_zap_plugin(self) -> None:
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

    def test_orchestrator_resolves_zap(self) -> None:
        from kingsec.application import ScannerPort
        from kingsec.bootstrap import Container
        from kingsec.infrastructure.scanner.orchestrator import ScannerOrchestrator
        from kingsec.infrastructure.scanner.plugins.zap import ZapPlugin
        from kingsec.infrastructure.scanner.registry import InMemoryPluginRegistry

        container = Container()
        runner = FakeRunner(CommandResult(0, _SAMPLE_JSONL, "", 0.0))

        # Register only the zap plugin
        registry = InMemoryPluginRegistry()
        zap_plugin = ZapPlugin(
            ZapSettings(binary_path="python"),
            runner=runner,
        )
        registry.register(zap_plugin)

        orchestrator = ScannerOrchestrator(registry)
        container.register_instance(ScannerPort, orchestrator)

        scanner = container.resolve(ScannerPort)
        findings = scanner.scan(_TARGET)
        assert len(findings) == 3
