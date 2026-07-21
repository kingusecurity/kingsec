"""Unit tests for NucleiScannerAdapter using a fake runner (no subprocess)."""

from __future__ import annotations

from pathlib import Path

import pytest

from kingsec.application import ScannerPort
from kingsec.bootstrap import Container
from kingsec.domain import Severity, Target, TargetType
from kingsec.infrastructure.config.models import ScannerSettings
from kingsec.infrastructure.scanner import (
    NucleiScannerAdapter,
    register_scanner,
)
from kingsec.infrastructure.scanner.errors import ScannerExecutionError
from kingsec.infrastructure.scanner.runner import CommandResult
from tests.unit.infrastructure.scanner.conftest import FakeRunner

_TARGET = Target("10.0.0.5", TargetType.IP_ADDRESS)
_SAMPLE = (
    '{"template-id":"t1","info":{"name":"Crit","severity":"critical"},'
    '"matched-at":"http://10.0.0.5/x"}'
)


class TestArgumentBuilding:
    def test_builds_safe_argument_list(self) -> None:
        runner = FakeRunner(CommandResult(0, "", "", 0.0))
        adapter = NucleiScannerAdapter(
            ScannerSettings(binary_path="/opt/nuclei", rate_limit=99), runner=runner
        )
        adapter.scan(_TARGET)

        argv, _timeout = runner.calls[0]
        # Target is a single argv element (cannot inject args), and flags are set.
        assert argv[0] == "/opt/nuclei"
        assert argv[1:3] == ["-u", "10.0.0.5"]
        assert "-jsonl" in argv and "-duc" in argv
        assert argv[argv.index("-rl") + 1] == "99"

    def test_templates_dir_added_when_configured(self, tmp_path: Path) -> None:
        runner = FakeRunner(CommandResult(0, "", "", 0.0))
        adapter = NucleiScannerAdapter(
            ScannerSettings(templates_dir=tmp_path), runner=runner
        )
        adapter.scan(_TARGET)
        argv = runner.calls[0][0]
        assert argv[argv.index("-t") + 1] == str(tmp_path)

    def test_timeout_from_settings_is_passed(self) -> None:
        runner = FakeRunner(CommandResult(0, "", "", 0.0))
        NucleiScannerAdapter(
            ScannerSettings(timeout_seconds=12.5), runner=runner
        ).scan(_TARGET)
        assert runner.calls[0][1] == 12.5


class TestScanResults:
    def test_success_returns_findings(self) -> None:
        runner = FakeRunner(CommandResult(0, _SAMPLE, "", 0.5))
        findings = NucleiScannerAdapter(ScannerSettings(), runner=runner).scan(_TARGET)
        assert len(findings) == 1
        assert findings[0].severity is Severity.CRITICAL

    def test_empty_output_returns_no_findings(self) -> None:
        runner = FakeRunner(CommandResult(0, "", "", 0.1))
        assert NucleiScannerAdapter(ScannerSettings(), runner=runner).scan(_TARGET) == []


class TestErrorTranslation:
    def test_nonzero_exit_raises_scanner_error(self) -> None:
        runner = FakeRunner(CommandResult(2, "", "fatal: bad flag", 0.1))
        with pytest.raises(ScannerExecutionError) as excinfo:
            NucleiScannerAdapter(ScannerSettings(), runner=runner).scan(_TARGET)
        assert excinfo.value.code == "KS-SCAN-001"

    def test_runner_timeout_propagates_as_scanner_error(self) -> None:
        runner = FakeRunner()
        runner.exception = ScannerExecutionError("scan timed out after 300s")
        with pytest.raises(ScannerExecutionError):
            NucleiScannerAdapter(ScannerSettings(), runner=runner).scan(_TARGET)

    def test_missing_templates_dir_fails_fast(self, tmp_path: Path) -> None:
        missing = tmp_path / "nope"
        runner = FakeRunner(CommandResult(0, "", "", 0.0))
        with pytest.raises(ScannerExecutionError, match="templates directory"):
            NucleiScannerAdapter(
                ScannerSettings(templates_dir=missing), runner=runner
            ).scan(_TARGET)
        # The process was never even launched.
        assert runner.calls == []


class TestRegistration:
    def test_register_scanner_binds_port(self) -> None:
        from kingsec.infrastructure.config import Settings
        from kingsec.infrastructure.config.models import NmapSettings, ScannerSettings

        container = Container()
        runner = FakeRunner(CommandResult(0, _SAMPLE, "", 0.0))
        settings = Settings()
        scanner_settings = ScannerSettings(binary_path="python")
        nmap_settings = NmapSettings(binary_path="python")
        settings = settings.model_copy(
            update={"scanner": scanner_settings, "nmap": nmap_settings}
        )
        register_scanner(container, settings, runner=runner)

        scanner = container.resolve(ScannerPort)
        from kingsec.infrastructure.scanner.orchestrator import ScannerOrchestrator
        assert isinstance(scanner, ScannerOrchestrator)
        assert len(scanner.scan(_TARGET)) == 1
