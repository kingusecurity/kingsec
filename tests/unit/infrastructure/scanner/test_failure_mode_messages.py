"""Phase 08: reproduction + regression for per-mode scanner failure messages.

Phase 07 correctly sanitized scanner errors at source, but every mode
collapsed to the same generic ScannerError.default_user_message ("The
security scan could not be completed."), because no raise site set its own
user_message=. This file proves 5 distinct, re-verified failure modes
(Phase 08 §3.1's inventory - going beyond Phase 04's original 3-mode
summary, per this phase's explicit re-verify-don't-copy instruction):

  M1 binary absent            runner.py:85-90   (all 9 adapters, shared site)
  M2 timeout                  runner.py:91-96   (all 9 adapters, shared site)
  M3 non-zero exit/no findings  9x adapter guard clause (identical shape)
  M4 templates directory missing  nuclei.py:123-130 (Nuclei only)
  M5 required wordlist missing    ffuf.py:75-81, gobuster.py:75-81

Written FIRST, before any fix, per Phase 08 ground rule #2. Run against
unmodified code, these fail because every mode currently renders the
identical generic string.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from kingsec.domain import Target, TargetType
from kingsec.infrastructure.config.models import (
    AmassSettings,
    FfufSettings,
    GobusterSettings,
    NiktoSettings,
    NmapSettings,
    ScannerSettings,
    SemgrepSettings,
    TrivySettings,
    ZapSettings,
)
from kingsec.infrastructure.scanner.amass import AmassScannerAdapter
from kingsec.infrastructure.scanner.errors import NONZERO_EXIT_USER_MESSAGE, ScannerExecutionError
from kingsec.infrastructure.scanner.ffuf import FfufScannerAdapter
from kingsec.infrastructure.scanner.gobuster import GobusterScannerAdapter
from kingsec.infrastructure.scanner.nikto import NiktoScannerAdapter
from kingsec.infrastructure.scanner.nmap import NmapScannerAdapter
from kingsec.infrastructure.scanner.nuclei import NucleiScannerAdapter
from kingsec.infrastructure.scanner.runner import CommandResult
from kingsec.infrastructure.scanner.semgrep import SemgrepScannerAdapter
from kingsec.infrastructure.scanner.trivy import TrivyScannerAdapter
from kingsec.infrastructure.scanner.zap import ZapScannerAdapter
from tests.unit.infrastructure.scanner.conftest import FakeRunner

_TARGET = Target("10.0.0.5", TargetType.IP_ADDRESS)
_GENERIC_DEFAULT = "The security scan could not be completed."


def _user_message(exc_ctx: pytest.ExceptionInfo[ScannerExecutionError]) -> str:
    exc = exc_ctx.value
    assert isinstance(exc, ScannerExecutionError)
    return exc.user_message


# ---------------------------------------------------------------------------
# M1: binary absent (real SubprocessCommandRunner - no FakeRunner, since
# runner.py's own FileNotFoundError translation is what's under test).
# ---------------------------------------------------------------------------


class TestBinaryAbsentMessage:
    def test_message_is_specific_and_not_generic(self, tmp_path: Path) -> None:
        adapter = NucleiScannerAdapter(ScannerSettings(binary_path=str(tmp_path / "does-not-exist")))
        with pytest.raises(ScannerExecutionError) as exc_ctx:
            adapter.scan(_TARGET)
        assert _user_message(exc_ctx) != _GENERIC_DEFAULT

    def test_message_names_the_problem(self, tmp_path: Path) -> None:
        adapter = NucleiScannerAdapter(ScannerSettings(binary_path=str(tmp_path / "does-not-exist")))
        with pytest.raises(ScannerExecutionError) as exc_ctx:
            adapter.scan(_TARGET)
        msg = _user_message(exc_ctx)
        assert "not be found" in msg or "not found" in msg

    def test_message_leaks_no_configured_path(self, tmp_path: Path) -> None:
        bogus = tmp_path / "does-not-exist-binary"
        adapter = NucleiScannerAdapter(ScannerSettings(binary_path=str(bogus)))
        with pytest.raises(ScannerExecutionError) as exc_ctx:
            adapter.scan(_TARGET)
        msg = _user_message(exc_ctx)
        assert str(bogus) not in msg
        assert "does-not-exist-binary" not in msg


# ---------------------------------------------------------------------------
# M2: timeout (real SubprocessCommandRunner + a genuinely slow executable).
# ---------------------------------------------------------------------------


def _trigger_timeout() -> pytest.ExceptionInfo[ScannerExecutionError]:
    # make_fake_nuclei's shebang-script technique (used elsewhere in this
    # repo's own test suite) does not execute directly on Windows -
    # subprocess.run() raises OSError [WinError 193] before the process ever
    # starts, never reaching the timeout. SubprocessCommandRunner is tested
    # directly here (still the real, unmodified runner.py code under test)
    # with a genuinely native, genuinely slow process instead.
    import sys

    from kingsec.infrastructure.scanner.runner import SubprocessCommandRunner

    runner = SubprocessCommandRunner()
    with pytest.raises(ScannerExecutionError) as exc_ctx:
        runner.run([sys.executable, "-c", "import time; time.sleep(30)"], timeout=0.5)
    return exc_ctx


class TestTimeoutMessage:
    def test_message_is_specific_and_not_generic(self) -> None:
        exc_ctx = _trigger_timeout()
        assert _user_message(exc_ctx) != _GENERIC_DEFAULT

    def test_message_mentions_timeout(self) -> None:
        exc_ctx = _trigger_timeout()
        assert "timeout" in _user_message(exc_ctx).lower() or "timed out" in _user_message(exc_ctx).lower()

    def test_message_leaks_no_binary_path(self) -> None:
        import sys

        exc_ctx = _trigger_timeout()
        msg = _user_message(exc_ctx)
        assert sys.executable not in msg


# ---------------------------------------------------------------------------
# M3: non-zero exit, no findings (identical shape in all 9 adapters).
# ---------------------------------------------------------------------------


class TestNonZeroExitMessage:
    def test_message_is_specific_and_not_generic(self) -> None:
        runner = FakeRunner(CommandResult(returncode=1, stdout="", stderr="fatal: bad flag", duration_seconds=0.1))
        adapter = NmapScannerAdapter(NmapSettings(), runner=runner)
        with pytest.raises(ScannerExecutionError) as exc_ctx:
            adapter.scan(_TARGET)
        assert _user_message(exc_ctx) != _GENERIC_DEFAULT

    def test_message_leaks_no_stderr_content(self) -> None:
        runner = FakeRunner(
            CommandResult(returncode=1, stdout="", stderr="panic: /etc/nmap/nmap-services missing", duration_seconds=0.1)
        )
        adapter = NmapScannerAdapter(NmapSettings(), runner=runner)
        with pytest.raises(ScannerExecutionError) as exc_ctx:
            adapter.scan(_TARGET)
        msg = _user_message(exc_ctx)
        assert "/etc/nmap" not in msg
        assert "panic" not in msg

    @pytest.mark.parametrize(
        "adapter_cls,settings_cls,settings_kwargs",
        [
            (NmapScannerAdapter, NmapSettings, {}),
            (NucleiScannerAdapter, ScannerSettings, {}),
            (NiktoScannerAdapter, NiktoSettings, {}),
            (FfufScannerAdapter, FfufSettings, {"wordlist": "wordlist.txt"}),
            (GobusterScannerAdapter, GobusterSettings, {"wordlist": "wordlist.txt"}),
            (AmassScannerAdapter, AmassSettings, {}),
            (TrivyScannerAdapter, TrivySettings, {}),
            (ZapScannerAdapter, ZapSettings, {}),
            (SemgrepScannerAdapter, SemgrepSettings, {}),
        ],
    )
    def test_all_9_adapters_share_identical_message(
        self, adapter_cls: type, settings_cls: type, settings_kwargs: dict[str, str]
    ) -> None:
        runner = FakeRunner(CommandResult(returncode=2, stdout="", stderr="", duration_seconds=0.1))
        adapter = adapter_cls(settings_cls(**settings_kwargs), runner=runner)
        with pytest.raises(ScannerExecutionError) as exc_ctx:
            adapter.scan(_TARGET)
        assert _user_message(exc_ctx) == NONZERO_EXIT_USER_MESSAGE


# ---------------------------------------------------------------------------
# M4: Nuclei templates directory missing.
# ---------------------------------------------------------------------------


class TestTemplatesDirMissingMessage:
    def test_message_is_specific_and_not_generic(self, tmp_path: Path) -> None:
        missing = tmp_path / "nonexistent-templates"
        adapter = NucleiScannerAdapter(ScannerSettings(templates_dir=missing))
        with pytest.raises(ScannerExecutionError) as exc_ctx:
            adapter.scan(_TARGET)
        assert _user_message(exc_ctx) != _GENERIC_DEFAULT

    def test_message_leaks_no_configured_path(self, tmp_path: Path) -> None:
        missing = tmp_path / "nonexistent-templates-dir-xyz"
        adapter = NucleiScannerAdapter(ScannerSettings(templates_dir=missing))
        with pytest.raises(ScannerExecutionError) as exc_ctx:
            adapter.scan(_TARGET)
        msg = _user_message(exc_ctx)
        assert str(missing) not in msg
        assert "nonexistent-templates-dir-xyz" not in msg


# ---------------------------------------------------------------------------
# M5: required wordlist missing (ffuf, gobuster).
# ---------------------------------------------------------------------------


class TestWordlistMissingMessage:
    def test_ffuf_message_is_specific_and_not_generic(self) -> None:
        adapter = FfufScannerAdapter(FfufSettings(wordlist=""))
        with pytest.raises(ScannerExecutionError) as exc_ctx:
            adapter.scan(_TARGET)
        assert _user_message(exc_ctx) != _GENERIC_DEFAULT

    def test_gobuster_message_is_specific_and_not_generic(self) -> None:
        adapter = GobusterScannerAdapter(GobusterSettings(wordlist=""))
        with pytest.raises(ScannerExecutionError) as exc_ctx:
            adapter.scan(_TARGET)
        assert _user_message(exc_ctx) != _GENERIC_DEFAULT

    def test_ffuf_and_gobuster_share_identical_wordlist_message(self) -> None:
        with pytest.raises(ScannerExecutionError) as ffuf_ctx:
            FfufScannerAdapter(FfufSettings(wordlist="")).scan(_TARGET)
        with pytest.raises(ScannerExecutionError) as gobuster_ctx:
            GobusterScannerAdapter(GobusterSettings(wordlist="")).scan(_TARGET)
        assert _user_message(ffuf_ctx) == _user_message(gobuster_ctx)


# ---------------------------------------------------------------------------
# Distinguishability: the test that proves the phase achieved its purpose.
# ---------------------------------------------------------------------------


class TestModesAreDistinguishableFromEachOther:
    def test_no_two_modes_produce_the_same_string(self, tmp_path: Path) -> None:
        messages: dict[str, str] = {}

        with pytest.raises(ScannerExecutionError) as ctx:
            NucleiScannerAdapter(ScannerSettings(binary_path=str(tmp_path / "nope"))).scan(_TARGET)
        messages["binary_absent"] = _user_message(ctx)

        messages["timeout"] = _user_message(_trigger_timeout())

        with pytest.raises(ScannerExecutionError) as ctx:
            runner = FakeRunner(CommandResult(returncode=1, stdout="", stderr="", duration_seconds=0.1))
            NmapScannerAdapter(NmapSettings(), runner=runner).scan(_TARGET)
        messages["nonzero_exit"] = _user_message(ctx)

        with pytest.raises(ScannerExecutionError) as ctx:
            NucleiScannerAdapter(ScannerSettings(templates_dir=tmp_path / "nope-templates")).scan(_TARGET)
        messages["templates_missing"] = _user_message(ctx)

        with pytest.raises(ScannerExecutionError) as ctx:
            FfufScannerAdapter(FfufSettings(wordlist="")).scan(_TARGET)
        messages["wordlist_missing"] = _user_message(ctx)

        values = list(messages.values())
        assert len(values) == len(set(values)), f"duplicate messages found: {messages}"
        for name, msg in messages.items():
            assert msg != _GENERIC_DEFAULT, f"{name} still renders the generic fallback"


# ---------------------------------------------------------------------------
# Phase 07 regression: an unvetted exception must still collapse to generic.
# ---------------------------------------------------------------------------


class TestUnvettedExceptionStillCollapsesToGeneric:
    """Phase 07's behavior for a genuinely unvetted exception must be
    unchanged by Phase 08's per-mode additions - proven at the orchestrator
    layer (where Phase 07's sanitization actually lives), not the adapter
    layer (adapters don't wrap exceptions themselves; the orchestrator's
    ScannerPluginPort wrapping does - see orchestrator.py's execute())."""

    def test_raw_connection_error_still_generic_and_safe(self) -> None:
        from kingsec.application.ports.scanner_plugin import ScannerPluginPort
        from kingsec.domain import (
            OutputFormat,
            PluginAvailability,
            PluginConfig,
            ScanCategory,
            ScannerCapability,
            ScannerId,
            ScannerPluginMetadata,
            ScannerResult,
        )
        from kingsec.infrastructure.scanner.orchestrator import ScannerOrchestrator
        from kingsec.infrastructure.scanner.registry import InMemoryPluginRegistry

        class _RaisingPlugin(ScannerPluginPort):
            def metadata(self) -> ScannerPluginMetadata:
                return ScannerPluginMetadata(
                    id=ScannerId("nuclei"), name="Nuclei Scanner", version="1.0.0",
                    author="Test", description="stub", api_version="1.0",
                )

            def capabilities(self) -> tuple[ScannerCapability, ...]:
                return (
                    ScannerCapability(
                        target_types=frozenset({TargetType.IP_ADDRESS}),
                        scan_categories=frozenset({ScanCategory.VULNERABILITY}),
                        output_format=OutputFormat.FINDINGS,
                    ),
                )

            def is_available(self) -> PluginAvailability:
                return PluginAvailability(available=True)

            def scan(self, target: Target, config: PluginConfig) -> ScannerResult:
                raise ConnectionError("Connection refused: internal-scanner.corp.local:9200")

            def health_check(self) -> None:
                pass

            def shutdown(self) -> None:
                pass

        registry = InMemoryPluginRegistry()
        registry.register(_RaisingPlugin())
        orchestrator = ScannerOrchestrator(registry)

        try:
            orchestrator.execute(_RaisingPlugin(), _TARGET, PluginConfig())
            raise AssertionError("expected ScannerPluginError")
        except Exception as exc:
            assert "internal-scanner.corp.local" not in str(exc)
            # A raw ConnectionError is neither KingSecError nor
            # ApplicationError, so safe_failure_message() falls through to
            # its final branch: KingSecError.default_user_message - a
            # DIFFERENT generic string than ScannerError's own
            # default_user_message (_GENERIC_DEFAULT above), which only
            # applies to ScannerExecutionError instances with no explicit
            # user_message. Getting these two constants mixed up was a bug
            # in this test's first draft, not a pre-fix product defect.
            assert "An unexpected error occurred. Please try again or contact support." in str(exc)
