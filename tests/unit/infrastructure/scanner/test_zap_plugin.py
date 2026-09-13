"""ZapPlugin: metadata, capabilities, availability, scan delegation, and provisioning."""

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
from kingsec.infrastructure.config.models import ZapSettings
from kingsec.infrastructure.scanner.errors import BINARY_ABSENT_USER_MESSAGE, ScannerExecutionError
from kingsec.infrastructure.scanner.plugins.zap import ZapPlugin
from kingsec.infrastructure.scanner.runner import CommandResult
from kingsec.infrastructure.scanner.zap import ZapScannerAdapter
from tests.unit.infrastructure.scanner.conftest import FakeRunner

_TARGET = Target("http://example.com", TargetType.URL)

_SAMPLE_ZAP_REPORT = json.dumps(
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


class _FileWritingRunner(FakeRunner):
    """FakeRunner that also writes to the ``-quickout`` path, mirroring the
    real ZAP.exe: its real report lands in the FILE, not stdout (Task 5B
    Priority 1). ``file_content=None`` simulates ZAP writing no file at
    all (e.g. a hard crash before it gets that far)."""

    def __init__(self, result: CommandResult, file_content: str | None) -> None:
        super().__init__(result)
        self._file_content = file_content

    def run(self, args, *, timeout: float, cwd: str | None = None) -> CommandResult:
        if self._file_content is not None:
            output_path = Path(args[args.index("-quickout") + 1])
            output_path.parent.mkdir(parents=True, exist_ok=True)
            output_path.write_text(self._file_content, encoding="utf-8")
        return super().run(args, timeout=timeout, cwd=cwd)


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


def _make_adapter(
    *,
    binary_path: str = "zap",
    runner: FakeRunner | None = None,
    data_dir: Path | None = None,
    scan_args: tuple[str, ...] = (),
) -> ZapScannerAdapter:
    settings = ZapSettings(binary_path=binary_path, scan_args=scan_args)
    return ZapScannerAdapter(settings, runner=runner, data_dir=data_dir)


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
    def test_declares_http_base_url(self) -> None:
        caps = _make_plugin().capabilities()
        assert len(caps) == 1
        assert caps[0].requirement is ScannerRequirement.HTTP_BASE_URL

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
        runner = _FileWritingRunner(CommandResult(0, "", "", 0.5), _SAMPLE_ZAP_REPORT)
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
        runner = _FileWritingRunner(CommandResult(0, "", "", 0.3), _SAMPLE_ZAP_REPORT)
        plugin = _make_plugin(runner=runner)
        result = plugin.scan(_TARGET, PluginConfig())
        assert isinstance(result, ScannerResult)
        assert result.scanner_id == ScannerId("zap")

    def test_build_args_includes_quickurl(self) -> None:
        adapter = _make_adapter()
        args, _cwd, _output_path = adapter._build_args(_TARGET)
        assert "-quickurl" in args

    def test_build_args_includes_target(self) -> None:
        adapter = _make_adapter()
        args, _cwd, _output_path = adapter._build_args(_TARGET)
        url_idx = args.index("-quickurl")
        assert args[url_idx + 1] == "http://example.com"

    def test_build_args_includes_quickout_with_a_real_json_file_path(self) -> None:
        """Task 5 output-path fix: -quickout is a real, writable file path
        (never the bare literal "json" - see TestOutputPath for the full
        regression coverage of where that path must live)."""
        adapter = _make_adapter()
        args, _cwd, output_path = adapter._build_args(_TARGET)
        assert "-quickout" in args
        out_idx = args.index("-quickout")
        assert args[out_idx + 1] != "json"
        assert args[out_idx + 1].endswith(".json")
        assert args[out_idx + 1] == str(output_path)


# ===========================================================================
# Task 5B Priority 1: read and parse the -quickout FILE, never stdout,
# and never trust returncode alone.
# ===========================================================================


class TestFileBasedSuccessCheck:
    """Every ZAP scan in this product's history returned zero findings
    while reporting success: parse_zap_json() read result.stdout, but ZAP
    writes its real JSON report to the -quickout FILE - stdout only ever
    carries a "Writing results to <path>" line and progress/log text.
    Success now requires: the file exists, is non-empty, and parses as
    ZAP-shaped JSON. returncode alone is not trustworthy either - -cmd
    can exit 0 while reporting a real configuration error with no output
    file at all (verified against the real binary)."""

    def test_exit_zero_with_no_output_file_is_failed_not_a_zero_findings_success(self, tmp_path: Path) -> None:
        """The exact shape of the real bug this priority exists to close:
        a clean exit code with nothing written must be a FAILURE, never
        a silent "succeeded, zero findings"."""
        runner = _FileWritingRunner(CommandResult(0, "", "", 0.1), file_content=None)
        adapter = _make_adapter(binary_path="python", runner=runner, data_dir=tmp_path)

        with pytest.raises(ScannerExecutionError) as exc_ctx:
            adapter.scan(_TARGET)
        assert "output file missing" in str(exc_ctx.value.context.get("check_failed", ""))

    def test_real_zap_json_output_file_parses_into_findings(self, tmp_path: Path) -> None:
        runner = _FileWritingRunner(CommandResult(0, "", "", 0.1), _SAMPLE_ZAP_REPORT)
        adapter = _make_adapter(binary_path="python", runner=runner, data_dir=tmp_path)

        findings = adapter.scan(_TARGET)

        assert len(findings) == 3
        titles = {f.title for f in findings}
        assert any("SQL Injection" in t for t in titles)
        assert any("XSS" in t for t in titles)
        assert any("Missing Header" in t for t in titles)

    def test_empty_output_file_is_failed(self, tmp_path: Path) -> None:
        runner = _FileWritingRunner(CommandResult(0, "", "", 0.1), file_content="")
        adapter = _make_adapter(binary_path="python", runner=runner, data_dir=tmp_path)

        with pytest.raises(ScannerExecutionError) as exc_ctx:
            adapter.scan(_TARGET)
        assert "empty" in str(exc_ctx.value.context.get("check_failed", ""))

    def test_malformed_json_in_output_file_is_failed(self, tmp_path: Path) -> None:
        runner = _FileWritingRunner(CommandResult(0, "", "", 0.1), file_content="{not valid json")
        adapter = _make_adapter(binary_path="python", runner=runner, data_dir=tmp_path)

        with pytest.raises(ScannerExecutionError) as exc_ctx:
            adapter.scan(_TARGET)
        assert "did not parse as JSON" in str(exc_ctx.value.context.get("check_failed", ""))

    def test_valid_json_missing_site_key_is_failed(self, tmp_path: Path) -> None:
        """Valid JSON that isn't shaped like a ZAP report (e.g. truncated,
        or some other tool's output landed at the same path) must not be
        silently treated as "zero findings" either."""
        runner = _FileWritingRunner(CommandResult(0, "", "", 0.1), file_content=json.dumps({"unrelated": True}))
        adapter = _make_adapter(binary_path="python", runner=runner, data_dir=tmp_path)

        with pytest.raises(ScannerExecutionError) as exc_ctx:
            adapter.scan(_TARGET)
        assert "site" in str(exc_ctx.value.context.get("check_failed", ""))

    def test_genuinely_clean_scan_is_a_legitimate_zero_findings_success(self, tmp_path: Path) -> None:
        """The flip side: once the file is confirmed to be a real, valid
        ZAP report, zero alerts in it is a legitimate clean result, not
        an error - the three checks above only rule out "never produced
        a real report," never "produced one with nothing in it."""
        runner = _FileWritingRunner(CommandResult(0, "", "", 0.1), file_content=json.dumps({"site": []}))
        adapter = _make_adapter(binary_path="python", runner=runner, data_dir=tmp_path)

        findings = adapter.scan(_TARGET)
        assert findings == []

    def test_cmd_exit_zero_with_unwritable_directory_error_is_failed(self, tmp_path: Path) -> None:
        """Reproduces the exact real-world failure verified against the
        binary: -cmd exits 0 while printing a configuration error to
        stdout, with no output file written at all."""
        runner = _FileWritingRunner(
            CommandResult(0, "The directory of given '-quickout' file is not writable: ...", "", 0.1),
            file_content=None,
        )
        adapter = _make_adapter(binary_path="python", runner=runner, data_dir=tmp_path)

        with pytest.raises(ScannerExecutionError):
            adapter.scan(_TARGET)


class TestOutputFileCleanup:
    """Task 5B Priority 1: the file lands in KingSec's own data directory
    and would otherwise accumulate one per scan forever."""

    def test_output_file_removed_after_a_successful_scan(self, tmp_path: Path) -> None:
        runner = _FileWritingRunner(CommandResult(0, "", "", 0.1), _SAMPLE_ZAP_REPORT)
        adapter = _make_adapter(binary_path="python", runner=runner, data_dir=tmp_path)

        adapter.scan(_TARGET)

        leftover = list((tmp_path / "scanner-output").glob("*.json"))
        assert leftover == []

    def test_output_file_removed_even_when_parsing_fails(self, tmp_path: Path) -> None:
        """Cleanup must happen on the failure path too - a scan that
        raises should not leave its (unusable) file behind either."""
        runner = _FileWritingRunner(CommandResult(0, "", "", 0.1), file_content="{not valid json")
        adapter = _make_adapter(binary_path="python", runner=runner, data_dir=tmp_path)

        with pytest.raises(ScannerExecutionError):
            adapter.scan(_TARGET)

        leftover = list((tmp_path / "scanner-output").glob("*.json"))
        assert leftover == []


# ===========================================================================
# Task 5B Priority 3: -cmd is a code-level default, never operator-strippable
# ===========================================================================


class TestHeadlessFlagIsNeverStrippable:
    def test_cmd_present_with_default_scan_args(self) -> None:
        adapter = _make_adapter()
        args, _cwd, _output_path = adapter._build_args(_TARGET)
        assert "-cmd" in args

    def test_cmd_present_regardless_of_operator_configured_scan_args(self) -> None:
        """scan_args is purely additive - it can never remove a hardcoded
        argv element, but this proves it directly rather than trusting
        that invariant by construction alone."""
        adapter = _make_adapter(scan_args=("-daemon", "-port", "8090"))
        args, _cwd, _output_path = adapter._build_args(_TARGET)
        assert "-cmd" in args

    def test_cmd_appears_immediately_after_the_binary(self) -> None:
        adapter = _make_adapter()
        args, _cwd, _output_path = adapter._build_args(_TARGET)
        assert args[1] == "-cmd"


# ===========================================================================
# Task 5: resolve binary_path via find_executable() and invoke with cwd
# ===========================================================================


class TestBinaryResolutionAndWorkingDirectory:
    """ZAP.exe (an install4j native launcher) resolves its own bundled
    classpath relative to ITS OWN directory, not the caller's - invoking
    it with the wrong cwd silently fails to find its jars. binary_path is
    now resolved to an absolute path through the SAME find_executable()
    doctor uses (one shared resolution function, Addition 2), and cwd is
    set to that binary's own directory."""

    def test_resolved_binary_becomes_argv0_and_cwd_is_its_directory(self, monkeypatch: pytest.MonkeyPatch) -> None:
        resolved = r"C:\Program Files\ZAP\Zed Attack Proxy\ZAP.exe"
        monkeypatch.setattr(
            "kingsec.infrastructure.scanner.zap.find_executable",
            lambda binary: resolved if binary == "zap" else None,
        )
        adapter = _make_adapter()
        args, cwd, _output_path = adapter._build_args(_TARGET)
        assert args[0] == resolved
        assert cwd == r"C:\Program Files\ZAP\Zed Attack Proxy"

    def test_unresolved_binary_falls_back_to_configured_string_with_no_cwd(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """When find_executable() can't resolve it (e.g. genuinely not
        installed), _build_args() must not guess a cwd - it falls back to
        the exact pre-existing behavior (configured string, no cwd), so
        the runner's own FileNotFoundError path still fires normally."""
        monkeypatch.setattr(
            "kingsec.infrastructure.scanner.zap.find_executable",
            lambda binary: None,
        )
        adapter = _make_adapter(binary_path="zap")
        args, cwd, _output_path = adapter._build_args(_TARGET)
        assert args[0] == "zap"
        assert cwd is None


class TestOutputPathNeverWritesIntoTheInstallDirectory:
    """Task 5 hang investigation: the real ZAP.exe popped a blocking GUI
    modal dialog because -quickout was a bare "json" string, resolved
    relative to cwd (ZAP's own install directory, not writable by the
    account running KingSec on the real Windows installer default,
    C:\\Program Files\\...). KingSec must write scanner output under its
    own configured data directory, never a scanner's install directory."""

    def test_quickout_path_is_under_the_configured_data_dir(self, tmp_path: Path) -> None:
        adapter = _make_adapter(binary_path="python", data_dir=tmp_path)

        args, _cwd, _output_path = adapter._build_args(_TARGET)

        out_idx = args.index("-quickout")
        quickout_path = args[out_idx + 1]
        assert quickout_path != "json"
        assert str(tmp_path) in quickout_path
        assert quickout_path.endswith(".json")

    def test_two_scans_get_different_quickout_filenames(self, tmp_path: Path) -> None:
        """Concurrent scans must not clobber each other's output file."""
        adapter = _make_adapter(binary_path="python", data_dir=tmp_path)

        first_args, _cwd1, _p1 = adapter._build_args(_TARGET)
        second_args, _cwd2, _p2 = adapter._build_args(_TARGET)

        assert first_args[first_args.index("-quickout") + 1] != second_args[second_args.index("-quickout") + 1]

    def test_default_data_dir_falls_back_to_kingsec_home_convention(self) -> None:
        """No data_dir passed (e.g. a direct construction in a test or
        script) must still default to somewhere real, matching the
        established ~/.kingsec convention, never a scanner's own install
        directory."""
        adapter = _make_adapter(binary_path="python")
        assert adapter._data_dir == Path.home() / ".kingsec"


# ===========================================================================
# Provisioning
# ===========================================================================


class TestProvisioning:
    def test_registry_contains_zap_plugin(self) -> None:
        from kingsec.bootstrap import Container
        from kingsec.infrastructure.config import Settings
        from kingsec.infrastructure.scanner import register_scanner

        container = Container()
        runner = _FileWritingRunner(CommandResult(0, "", "", 0.0), _SAMPLE_ZAP_REPORT)
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
        runner = _FileWritingRunner(CommandResult(0, "", "", 0.0), _SAMPLE_ZAP_REPORT)

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
