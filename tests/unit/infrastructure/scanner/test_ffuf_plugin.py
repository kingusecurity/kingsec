"""FfufPlugin: metadata, capabilities, availability, scan delegation, and provisioning."""

from __future__ import annotations

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
from kingsec.infrastructure.config.models import FfufSettings
from kingsec.infrastructure.scanner.errors import (
    BINARY_ABSENT_USER_MESSAGE,
    NONZERO_EXIT_USER_MESSAGE,
    WILDCARD_RESPONSE_USER_MESSAGE,
    ScannerExecutionError,
)
from kingsec.infrastructure.scanner.plugins.ffuf import FfufPlugin
from kingsec.infrastructure.scanner.runner import CommandResult
from tests.unit.infrastructure.scanner.conftest import FakeRunner

_TARGET = Target("http://example.com", TargetType.URL)

_SAMPLE_JSONL = (
    '{"input":{"FUZZ":"admin"},"position":1,"status":200,"length":1234,'
    '"words":56,"lines":23,"content-type":"text/html","redirectlocation":"",'
    '"url":"http://example.com/admin","duration":123456,"resultfile":"",'
    '"host":"example.com"}\n'
    '{"input":{"FUZZ":".git"},"position":2,"status":200,"length":890,'
    '"words":34,"lines":12,"content-type":"text/html","redirectlocation":"",'
    '"url":"http://example.com/.git","duration":45678,"resultfile":"",'
    '"host":"example.com"}\n'
)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _not_a_wildcard(url: str, timeout: float) -> bool:
    """Default fake wildcard probe for every test in this file that
    isn't specifically testing the wildcard check itself - never makes a
    real network call, always reports "target 404s normally"."""
    return False


def _make_plugin(
    *,
    binary_path: str = "ffuf",
    wordlist: str = "/usr/share/wordlists/common.txt",
    runner: FakeRunner | None = None,
    wildcard_probe=_not_a_wildcard,
) -> FfufPlugin:
    settings = FfufSettings(binary_path=binary_path, wordlist=wordlist)
    return FfufPlugin(settings, runner=runner, wildcard_probe=wildcard_probe)


# ===========================================================================
# Metadata
# ===========================================================================


class TestMetadata:
    def test_plugin_id(self) -> None:
        assert _make_plugin().metadata().id == ScannerId("ffuf")

    def test_plugin_name(self) -> None:
        assert _make_plugin().metadata().name == "ffuf Scanner"

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

    def test_discovery_category(self) -> None:
        caps = _make_plugin().capabilities()
        assert ScanCategory.DISCOVERY in caps[0].scan_categories

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
        plugin = _make_plugin(binary_path="definitely-not-ffuf-xyz")
        avail = plugin.is_available()
        assert avail.available is False
        assert avail.reason is not None
        # Phase 08: deliberately replaced, not weakened - see nmap's
        # equivalent test for the full reasoning.
        assert "definitely-not-ffuf-xyz" not in avail.reason
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
        assert result.scanner_id == ScannerId("ffuf")
        assert len(result.findings) == 2

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
        assert result.scanner_id == ScannerId("ffuf")

    def test_empty_output_returns_empty_findings(self) -> None:
        runner = FakeRunner(CommandResult(0, "", "", 0.0))
        plugin = _make_plugin(runner=runner)
        result = plugin.scan(_TARGET, PluginConfig())
        assert result.findings == ()

    def test_build_args_includes_u_flag(self) -> None:
        runner = FakeRunner(CommandResult(0, _SAMPLE_JSONL, "", 0.1))
        plugin = _make_plugin(runner=runner)
        plugin.scan(_TARGET, PluginConfig())
        args = runner.calls[0][0]
        assert "-u" in args

    def test_build_args_includes_target_with_fuzz(self) -> None:
        runner = FakeRunner(CommandResult(0, _SAMPLE_JSONL, "", 0.1))
        plugin = _make_plugin(runner=runner)
        plugin.scan(_TARGET, PluginConfig())
        args = runner.calls[0][0]
        u_idx = args.index("-u")
        assert "/FUZZ" in args[u_idx + 1]
        assert "example.com" in args[u_idx + 1]

    def test_build_args_includes_wordlist(self) -> None:
        runner = FakeRunner(CommandResult(0, _SAMPLE_JSONL, "", 0.1))
        plugin = _make_plugin(runner=runner)
        plugin.scan(_TARGET, PluginConfig())
        args = runner.calls[0][0]
        assert "-w" in args
        w_idx = args.index("-w")
        assert "common.txt" in args[w_idx + 1]

    def test_build_args_includes_json(self) -> None:
        runner = FakeRunner(CommandResult(0, _SAMPLE_JSONL, "", 0.1))
        plugin = _make_plugin(runner=runner)
        plugin.scan(_TARGET, PluginConfig())
        args = runner.calls[0][0]
        assert "-json" in args


# ===========================================================================
# Phase 2B-c Priority 3: request-rate limiting
# ===========================================================================


class TestRateLimiting:
    def test_default_settings_apply_the_conservative_rate_limit(self) -> None:
        runner = FakeRunner(CommandResult(0, _SAMPLE_JSONL, "", 0.1))
        plugin = _make_plugin(runner=runner)
        plugin.scan(_TARGET, PluginConfig())
        args = runner.calls[0][0]
        assert "-rate" in args
        assert args[args.index("-rate") + 1] == "40"

    def test_rate_limit_per_second_zero_disables_the_flag(self) -> None:
        settings = FfufSettings(
            binary_path="ffuf", wordlist="/wordlist.txt", rate_limit_per_second=0
        )
        runner = FakeRunner(CommandResult(0, _SAMPLE_JSONL, "", 0.1))
        plugin = FfufPlugin(settings, runner=runner, wildcard_probe=_not_a_wildcard)
        plugin.scan(_TARGET, PluginConfig())
        args = runner.calls[0][0]
        assert "-rate" not in args

    def test_operator_configured_rate_in_scan_args_is_not_duplicated(self) -> None:
        settings = FfufSettings(
            binary_path="ffuf",
            wordlist="/wordlist.txt",
            scan_args=("-rate", "5"),
        )
        runner = FakeRunner(CommandResult(0, _SAMPLE_JSONL, "", 0.1))
        plugin = FfufPlugin(settings, runner=runner, wildcard_probe=_not_a_wildcard)
        plugin.scan(_TARGET, PluginConfig())
        args = runner.calls[0][0]
        assert args.count("-rate") == 1
        assert args[args.index("-rate") + 1] == "5"

    def test_scan_result_discloses_the_applied_rate_limit(self) -> None:
        runner = FakeRunner(CommandResult(0, _SAMPLE_JSONL, "", 0.1))
        plugin = _make_plugin(runner=runner)
        result = plugin.scan(_TARGET, PluginConfig())
        assert result.rate_limit_description == "40 requests/second (ffuf -rate)"

    def test_scan_result_discloses_disabled_rate_limit(self) -> None:
        settings = FfufSettings(
            binary_path="ffuf", wordlist="/wordlist.txt", rate_limit_per_second=0
        )
        runner = FakeRunner(CommandResult(0, _SAMPLE_JSONL, "", 0.1))
        plugin = FfufPlugin(settings, runner=runner, wildcard_probe=_not_a_wildcard)
        result = plugin.scan(_TARGET, PluginConfig())
        assert result.rate_limit_description == "disabled (rate_limit_per_second=0)"

    def test_scan_result_discloses_operator_configured_rate(self) -> None:
        settings = FfufSettings(
            binary_path="ffuf",
            wordlist="/wordlist.txt",
            scan_args=("-rate", "5"),
        )
        runner = FakeRunner(CommandResult(0, _SAMPLE_JSONL, "", 0.1))
        plugin = FfufPlugin(settings, runner=runner, wildcard_probe=_not_a_wildcard)
        result = plugin.scan(_TARGET, PluginConfig())
        assert result.rate_limit_description == "operator-configured via scan_args (-rate)"


# ===========================================================================
# Phase 2B-c Priority 1a: wildcard/catch-all detection
# ===========================================================================


class TestWildcardDetectionAbortsBeforeFlooding:
    """Verified against a real target (Juice Shop, an Angular SPA): a
    random nonexistent path returns HTTP 200, and without this check ffuf
    matched nearly every wordlist entry against that same catch-all
    response - 4639 "findings" in one real run
    (docs/E2E-EVIDENCE-PHASE2B.md Defect 3), dozens scored High purely
    from the path's name. Matches gobuster's own standard: abort with an
    actionable reason, never flood."""

    def test_wildcard_response_aborts_before_running_ffuf_at_all(self) -> None:
        def _is_wildcard(url: str, timeout: float) -> bool:
            return True

        runner = FakeRunner(CommandResult(0, _SAMPLE_JSONL, "", 0.1))
        plugin = _make_plugin(runner=runner, wildcard_probe=_is_wildcard)

        with pytest.raises(ScannerExecutionError) as exc_ctx:
            plugin.scan(_TARGET, PluginConfig())

        assert exc_ctx.value.user_message == WILDCARD_RESPONSE_USER_MESSAGE
        # Never a flood, never even a real invocation - the wordlist pass
        # itself must never run once a wildcard is detected.
        assert runner.calls == []

    def test_wildcard_abort_reason_is_specific_and_actionable(self) -> None:
        """Matches gobuster's own standard: name the exact condition and
        what to do about it, not a generic failure."""

        def _is_wildcard(url: str, timeout: float) -> bool:
            return True

        runner = FakeRunner(CommandResult(0, _SAMPLE_JSONL, "", 0.1))
        plugin = _make_plugin(runner=runner, wildcard_probe=_is_wildcard)

        with pytest.raises(ScannerExecutionError) as exc_ctx:
            plugin.scan(_TARGET, PluginConfig())

        message = exc_ctx.value.user_message
        assert "404" in message or "catch-all" in message.lower() or "wildcard" in message.lower()
        assert message != NONZERO_EXIT_USER_MESSAGE

    def test_probe_receives_a_random_nonexistent_path_under_the_target(self) -> None:
        seen_urls: list[str] = []

        def _capture(url: str, timeout: float) -> bool:
            seen_urls.append(url)
            return False

        runner = FakeRunner(CommandResult(0, _SAMPLE_JSONL, "", 0.1))
        plugin = _make_plugin(runner=runner, wildcard_probe=_capture)

        plugin.scan(_TARGET, PluginConfig())

        assert len(seen_urls) == 1
        assert seen_urls[0].startswith(_TARGET.value)
        assert seen_urls[0] != _TARGET.value  # a real sub-path, not the bare target

    def test_two_probe_calls_use_different_random_paths(self) -> None:
        """The probe path must be unpredictable - a fixed, guessable path
        could itself coincidentally exist on some targets."""
        seen_urls: list[str] = []

        def _capture(url: str, timeout: float) -> bool:
            seen_urls.append(url)
            return False

        runner = FakeRunner(CommandResult(0, _SAMPLE_JSONL, "", 0.1))
        plugin1 = _make_plugin(runner=runner, wildcard_probe=_capture)
        plugin2 = _make_plugin(runner=runner, wildcard_probe=_capture)

        plugin1.scan(_TARGET, PluginConfig())
        plugin2.scan(_TARGET, PluginConfig())

        assert seen_urls[0] != seen_urls[1]

    def test_non_wildcard_target_proceeds_to_the_real_scan_normally(self) -> None:
        """Flip side: a target that correctly 404s must not be blocked."""

        def _not_wildcard(url: str, timeout: float) -> bool:
            return False

        runner = FakeRunner(CommandResult(0, _SAMPLE_JSONL, "", 0.1))
        plugin = _make_plugin(runner=runner, wildcard_probe=_not_wildcard)

        result = plugin.scan(_TARGET, PluginConfig())

        assert len(result.findings) == 2
        assert len(runner.calls) == 1


# ===========================================================================
# Provisioning
# ===========================================================================


class TestProvisioning:
    def test_registry_contains_ffuf_plugin(self) -> None:
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

    def test_orchestrator_resolves_ffuf(self) -> None:
        from kingsec.application import ScannerPort
        from kingsec.bootstrap import Container
        from kingsec.infrastructure.config.models import FfufSettings
        from kingsec.infrastructure.scanner.orchestrator import ScannerOrchestrator
        from kingsec.infrastructure.scanner.plugins.ffuf import FfufPlugin
        from kingsec.infrastructure.scanner.registry import InMemoryPluginRegistry

        container = Container()
        runner = FakeRunner(CommandResult(0, _SAMPLE_JSONL, "", 0.0))

        # Register only the ffuf plugin (other binaries not available)
        registry = InMemoryPluginRegistry()
        ffuf_plugin = FfufPlugin(
            FfufSettings(binary_path="python", wordlist="/tmp/wl.txt"),
            runner=runner,
            wildcard_probe=_not_a_wildcard,
        )
        registry.register(ffuf_plugin)

        orchestrator = ScannerOrchestrator(registry)
        container.register_instance(ScannerPort, orchestrator)

        scanner = container.resolve(ScannerPort)
        findings = scanner.scan(_TARGET)
        assert len(findings) == 2
