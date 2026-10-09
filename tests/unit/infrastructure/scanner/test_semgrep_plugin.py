"""SemgrepPlugin: metadata, capabilities, availability, scan delegation, and provisioning."""

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
from kingsec.infrastructure.config.models import SemgrepSettings
from kingsec.infrastructure.scanner.errors import (
    BINARY_ABSENT_USER_MESSAGE,
    ScannerExecutionError,
    ScannerOutputError,
)
from kingsec.infrastructure.scanner.plugins.semgrep import SemgrepPlugin
from kingsec.infrastructure.scanner.runner import CommandResult
from tests.unit.infrastructure.scanner.conftest import FakeRunner

_TARGET = Target(str(Path(__file__).resolve().parent), TargetType.SOURCE_PATH)

_SAMPLE_JSONL = json.dumps(
    {
        "results": [
            {
                "check_id": "python.lang.security.audit.hardcoded-password",
                "path": "config.py",
                "start": {"line": 5, "col": 1},
                "end": {"line": 5, "col": 30},
                "extra": {
                    "message": "Hardcoded password",
                    "severity": "ERROR",
                    "metadata": {"category": "security", "confidence": "HIGH"},
                },
            },
            {
                "check_id": "python.lang.security.audit.dangerous-system-call",
                "path": "utils.py",
                "start": {"line": 12, "col": 1},
                "end": {"line": 12, "col": 40},
                "extra": {
                    "message": "Dangerous system call",
                    "severity": "WARNING",
                    "metadata": {"category": "security", "confidence": "MEDIUM"},
                },
            },
            {
                "check_id": "python.best-practice.use-logging",
                "path": "main.py",
                "start": {"line": 8, "col": 1},
                "end": {"line": 8, "col": 20},
                "extra": {
                    "message": "Use logging",
                    "severity": "INFO",
                    "metadata": {"category": "best-practice", "confidence": "LOW"},
                },
            },
        ]
    }
)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _make_plugin(
    *,
    binary_path: str = "semgrep",
    rules: str = "",
    runner: FakeRunner | None = None,
) -> SemgrepPlugin:
    settings = SemgrepSettings(binary_path=binary_path, rules=rules)
    return SemgrepPlugin(settings, runner=runner)


# ===========================================================================
# Metadata
# ===========================================================================


class TestMetadata:
    def test_plugin_id(self) -> None:
        assert _make_plugin().metadata().id == ScannerId("semgrep")

    def test_plugin_name(self) -> None:
        assert _make_plugin().metadata().name == "Semgrep"

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
    def test_declares_source_path(self) -> None:
        caps = _make_plugin().capabilities()
        assert len(caps) == 1
        assert caps[0].requirement is ScannerRequirement.SOURCE_PATH

    def test_vulnerability_category(self) -> None:
        caps = _make_plugin().capabilities()
        assert ScanCategory.VULNERABILITY in caps[0].scan_categories

    def test_information_category(self) -> None:
        caps = _make_plugin().capabilities()
        assert ScanCategory.INFORMATION in caps[0].scan_categories

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
        plugin = _make_plugin(binary_path="definitely-not-semgrep-xyz")
        avail = plugin.is_available()
        assert avail.available is False
        assert avail.reason is not None
        # Phase 08: deliberately replaced, not weakened - see nmap's
        # equivalent test for the full reasoning.
        assert "definitely-not-semgrep-xyz" not in avail.reason
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
        assert result.scanner_id == ScannerId("semgrep")
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
        assert result.scanner_id == ScannerId("semgrep")

    def test_empty_output_raises_output_error(self) -> None:
        runner = FakeRunner(CommandResult(0, "", "", 0.0))
        plugin = _make_plugin(runner=runner)
        with pytest.raises(ScannerOutputError):
            plugin.scan(_TARGET, PluginConfig())

    def test_valid_empty_report_returns_empty_findings(self) -> None:
        runner = FakeRunner(CommandResult(0, json.dumps({"results": []}), "", 0.0))
        plugin = _make_plugin(runner=runner)
        result = plugin.scan(_TARGET, PluginConfig())
        assert result.findings == ()

    def test_malformed_nonempty_output_raises_output_error(self) -> None:
        runner = FakeRunner(CommandResult(0, "not semgrep json", "", 0.0))
        plugin = _make_plugin(runner=runner)
        with pytest.raises(ScannerOutputError):
            plugin.scan(_TARGET, PluginConfig())

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
        monkeypatch.setattr("kingsec.infrastructure.scanner.semgrep.os.access", lambda *_args: False)

        with pytest.raises(ScannerExecutionError) as exc_info:
            plugin.scan(_TARGET, PluginConfig())

        assert runner.calls == []
        assert "readable" in exc_info.value.user_message
        assert _TARGET.value not in exc_info.value.user_message

    def test_build_args_includes_scan_subcommand(self) -> None:
        runner = FakeRunner(CommandResult(0, _SAMPLE_JSONL, "", 0.1))
        plugin = _make_plugin(runner=runner)
        plugin.scan(_TARGET, PluginConfig())
        args = runner.calls[0][0]
        assert "scan" in args

    def test_build_args_includes_json_flag(self) -> None:
        runner = FakeRunner(CommandResult(0, _SAMPLE_JSONL, "", 0.1))
        plugin = _make_plugin(runner=runner)
        plugin.scan(_TARGET, PluginConfig())
        args = runner.calls[0][0]
        assert "--json" in args

    def test_build_args_includes_target(self) -> None:
        runner = FakeRunner(CommandResult(0, _SAMPLE_JSONL, "", 0.1))
        plugin = _make_plugin(runner=runner)
        plugin.scan(_TARGET, PluginConfig())
        args = runner.calls[0][0]
        assert _TARGET.value in args

    def test_build_args_includes_config_when_rules_set(self) -> None:
        runner = FakeRunner(CommandResult(0, _SAMPLE_JSONL, "", 0.1))
        plugin = _make_plugin(rules="/path/to/rules", runner=runner)
        plugin.scan(_TARGET, PluginConfig())
        args = runner.calls[0][0]
        assert "--config" in args
        cfg_idx = args.index("--config")
        assert args[cfg_idx + 1] == "/path/to/rules"

    def test_build_args_no_config_when_rules_empty(self) -> None:
        runner = FakeRunner(CommandResult(0, _SAMPLE_JSONL, "", 0.1))
        plugin = _make_plugin(rules="", runner=runner)
        plugin.scan(_TARGET, PluginConfig())
        args = runner.calls[0][0]
        assert "--config" not in args


# ===========================================================================
# Provisioning
# ===========================================================================


class TestProvisioning:
    def test_registry_contains_semgrep_plugin(self) -> None:
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

    def test_orchestrator_resolves_semgrep(self) -> None:
        from kingsec.application import ScannerPort
        from kingsec.bootstrap import Container
        from kingsec.infrastructure.scanner.orchestrator import ScannerOrchestrator
        from kingsec.infrastructure.scanner.plugins.semgrep import SemgrepPlugin
        from kingsec.infrastructure.scanner.registry import InMemoryPluginRegistry

        container = Container()
        runner = FakeRunner(CommandResult(0, _SAMPLE_JSONL, "", 0.0))

        # Register only the semgrep plugin
        registry = InMemoryPluginRegistry()
        semgrep_plugin = SemgrepPlugin(
            SemgrepSettings(binary_path="python"),
            runner=runner,
        )
        registry.register(semgrep_plugin)

        orchestrator = ScannerOrchestrator(registry)
        container.register_instance(ScannerPort, orchestrator)

        scanner = container.resolve(ScannerPort)
        findings = scanner.scan(_TARGET)
        assert len(findings) == 3
