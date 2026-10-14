"""ScannerOrchestrator: execute, execute_all, scan, and shutdown."""

from __future__ import annotations

import threading
import time

import pytest

from kingsec.application.assessment_execution import AssessmentExecutionEngine, ExecutionPhase
from kingsec.application.errors import ScannerPluginError
from kingsec.application.ports.scanner_plugin import ScannerPluginPort
from kingsec.application.ports.services import ScannerPort
from kingsec.domain import (
    Finding,
    OutputFormat,
    PluginAvailability,
    PluginConfig,
    ScanCategory,
    ScannerCapability,
    ScannerId,
    ScannerPluginMetadata,
    ScannerRequirement,
    ScannerResult,
    ScannerSurfaceTier,
    Severity,
    Target,
    TargetType,
)
from kingsec.domain.enums import ScannerRunState
from kingsec.infrastructure.config.models import OrchestratorSettings
from kingsec.infrastructure.scanner.errors import ScannerExecutionError
from kingsec.infrastructure.scanner.orchestrator import ScannerOrchestrator
from kingsec.infrastructure.scanner.registry import InMemoryPluginRegistry
from kingsec.infrastructure.scanner.runner import SubprocessCommandRunner

# ---------------------------------------------------------------------------
# Helpers: fake plugins
# ---------------------------------------------------------------------------


class _StubPlugin(ScannerPluginPort):
    """Configurable fake plugin for testing."""

    def __init__(
        self,
        *,
        plugin_id: str = "stub",
        findings: tuple[Finding, ...] = (),
        available: bool = True,
        availability_reason: str | None = None,
        raise_on_health: Exception | None = None,
        raise_on_scan: Exception | None = None,
        raise_on_shutdown: Exception | None = None,
        requirement: ScannerRequirement = ScannerRequirement.REACHABLE_HOST,
    ) -> None:
        self._id = plugin_id
        self._findings = findings
        self._available = available
        self._availability_reason = availability_reason
        self._raise_on_health = raise_on_health
        self._raise_on_scan = raise_on_scan
        self._raise_on_shutdown = raise_on_shutdown
        self._requirement = requirement
        self.shutdown_called = False

    def metadata(self) -> ScannerPluginMetadata:
        return ScannerPluginMetadata(
            id=ScannerId(self._id),
            name=f"Stub {self._id}",
            version="1.0.0",
            author="Test",
            description=f"Stub plugin {self._id}",
            api_version="1.0",
        )

    def capabilities(self) -> tuple[ScannerCapability, ...]:
        return (
            ScannerCapability(
                requirement=self._requirement,
                scan_categories=frozenset({ScanCategory.VULNERABILITY}),
                output_format=OutputFormat.FINDINGS,
                surface_tier=ScannerSurfaceTier.HOST_PORT_ANY_PATH,
            ),
        )

    def is_available(self) -> PluginAvailability:
        return PluginAvailability(
            available=self._available,
            reason=self._availability_reason,
        )

    def scan(self, target: Target, config: PluginConfig) -> ScannerResult:
        if self._raise_on_scan is not None:
            raise self._raise_on_scan
        return ScannerResult(
            scanner_id=ScannerId(self._id),
            findings=self._findings,
            raw_output="",
            duration_seconds=0.1,
        )

    def health_check(self) -> None:
        if self._raise_on_health is not None:
            raise self._raise_on_health

    def shutdown(self) -> None:
        self.shutdown_called = True
        if self._raise_on_shutdown is not None:
            raise self._raise_on_shutdown


class _UrlPlugin(ScannerPluginPort):
    """Plugin that matches URL targets only."""

    def __init__(self, plugin_id: str = "url-scan") -> None:
        self._id = plugin_id

    def metadata(self) -> ScannerPluginMetadata:
        return ScannerPluginMetadata(
            id=ScannerId(self._id),
            name="URL Scanner",
            version="1.0.0",
            author="Test",
            description="URL-only scanner",
            api_version="1.0",
        )

    def capabilities(self) -> tuple[ScannerCapability, ...]:
        return (
            ScannerCapability(
                requirement=ScannerRequirement.HTTP_BASE_URL,
                scan_categories=frozenset({ScanCategory.VULNERABILITY}),
                output_format=OutputFormat.FINDINGS,
                surface_tier=ScannerSurfaceTier.HOST_PORT_ANY_PATH,
            ),
        )

    def is_available(self) -> PluginAvailability:
        return PluginAvailability(available=True)

    def scan(self, target: Target, config: PluginConfig) -> ScannerResult:
        return ScannerResult(
            scanner_id=ScannerId(self._id),
            findings=(),
            raw_output="",
            duration_seconds=0.0,
        )

    def health_check(self) -> None:
        pass

    def shutdown(self) -> None:
        pass


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


@pytest.fixture
def registry() -> InMemoryPluginRegistry:
    return InMemoryPluginRegistry()


@pytest.fixture
def orchestrator(registry: InMemoryPluginRegistry) -> ScannerOrchestrator:
    return ScannerOrchestrator(registry)


@pytest.fixture
def fake_ip() -> Target:
    return Target("10.0.0.5", TargetType.IP_ADDRESS)


@pytest.fixture
def fake_url() -> Target:
    return Target("https://example.com", TargetType.URL)


def _finding(title: str = "SQL Injection", severity: Severity = Severity.HIGH) -> Finding:
    return Finding.create(title, "desc", severity)


# ===========================================================================
# execute()
# ===========================================================================


class TestExecute:
    def test_executes_plugin(self, orchestrator: ScannerOrchestrator) -> None:
        plugin = _StubPlugin(findings=(_finding(),))
        result = orchestrator.execute(plugin, Target("10.0.0.5", TargetType.IP_ADDRESS), PluginConfig())
        assert len(result.findings) == 1

    def test_health_check_called_first(self, orchestrator: ScannerOrchestrator) -> None:
        health_called = False

        class TrackingPlugin(_StubPlugin):
            def health_check(self_nonlocal) -> None:
                nonlocal health_called
                health_called = True

        plugin = TrackingPlugin()
        orchestrator.execute(plugin, Target("10.0.0.5", TargetType.IP_ADDRESS), PluginConfig())
        assert health_called is True

    def test_scan_called_second(self, orchestrator: ScannerOrchestrator) -> None:
        scan_called = False

        class TrackingPlugin(_StubPlugin):
            def scan(self_nonlocal, target, config) -> ScannerResult:
                nonlocal scan_called
                scan_called = True
                return ScannerResult(
                    scanner_id=ScannerId("track"),
                    findings=(),
                    raw_output="",
                    duration_seconds=0.0,
                )

        plugin = TrackingPlugin()
        orchestrator.execute(plugin, Target("10.0.0.5", TargetType.IP_ADDRESS), PluginConfig())
        assert scan_called is True

    def test_returns_scanner_result(self, orchestrator: ScannerOrchestrator) -> None:
        plugin = _StubPlugin(findings=(_finding(),))
        result = orchestrator.execute(plugin, Target("10.0.0.5", TargetType.IP_ADDRESS), PluginConfig())
        assert isinstance(result, ScannerResult)

    def test_plugin_error_propagated(self, orchestrator: ScannerOrchestrator) -> None:
        plugin = _StubPlugin(raise_on_health=ScannerPluginError("unavailable"))
        with pytest.raises(ScannerPluginError, match="unavailable"):
            orchestrator.execute(plugin, Target("10.0.0.5", TargetType.IP_ADDRESS), PluginConfig())

    def test_unexpected_error_wrapped(self, orchestrator: ScannerOrchestrator) -> None:
        plugin = _StubPlugin(raise_on_health=RuntimeError("oops"))
        with pytest.raises(ScannerPluginError, match="unexpected"):
            orchestrator.execute(plugin, Target("10.0.0.5", TargetType.IP_ADDRESS), PluginConfig())

    def test_scan_error_wrapped(self, orchestrator: ScannerOrchestrator) -> None:
        plugin = _StubPlugin(raise_on_scan=ValueError("bad target"))
        with pytest.raises(ScannerPluginError, match="unexpected"):
            orchestrator.execute(plugin, Target("10.0.0.5", TargetType.IP_ADDRESS), PluginConfig())


# ===========================================================================
# execute_all()
# ===========================================================================


class TestExecuteAll:
    def test_single_plugin(
        self, registry: InMemoryPluginRegistry, orchestrator: ScannerOrchestrator, fake_ip: Target
    ) -> None:
        registry.register(_StubPlugin(plugin_id="nuclei", findings=(_finding(),)))
        results = orchestrator.execute_all(fake_ip)
        assert len(results) == 1
        assert results[0].scanner_id == ScannerId("nuclei")

    def test_multiple_plugins(
        self, registry: InMemoryPluginRegistry, orchestrator: ScannerOrchestrator, fake_ip: Target
    ) -> None:
        registry.register(_StubPlugin(plugin_id="nuclei"))
        registry.register(_StubPlugin(plugin_id="nmap"))
        results = orchestrator.execute_all(fake_ip)
        assert len(results) == 2

    def test_one_plugin_fails_others_continue(
        self, registry: InMemoryPluginRegistry, orchestrator: ScannerOrchestrator, fake_ip: Target
    ) -> None:
        registry.register(_StubPlugin(plugin_id="good"))
        registry.register(_StubPlugin(plugin_id="bad", raise_on_health=ScannerPluginError("broken")))
        results = orchestrator.execute_all(fake_ip)
        assert len(results) == 1
        assert results[0].scanner_id == ScannerId("good")

    def test_configs_passed_correctly(
        self, registry: InMemoryPluginRegistry, orchestrator: ScannerOrchestrator, fake_ip: Target
    ) -> None:
        received_configs: list[PluginConfig] = []

        class ConfigCapture(_StubPlugin):
            def scan(self_nonlocal, target, config) -> ScannerResult:
                received_configs.append(config)
                return ScannerResult(
                    scanner_id=ScannerId("cap"),
                    findings=(),
                    raw_output="",
                    duration_seconds=0.0,
                )

        registry.register(ConfigCapture(plugin_id="cap"))
        custom = PluginConfig(settings={"timeout": 60})
        orchestrator.execute_all(fake_ip, configs={ScannerId("cap"): custom})
        assert len(received_configs) == 1
        assert received_configs[0].settings["timeout"] == 60

    def test_default_config_when_not_in_configs(
        self, registry: InMemoryPluginRegistry, orchestrator: ScannerOrchestrator, fake_ip: Target
    ) -> None:
        received_configs: list[PluginConfig] = []

        class ConfigCapture(_StubPlugin):
            def scan(self_nonlocal, target, config) -> ScannerResult:
                received_configs.append(config)
                return ScannerResult(
                    scanner_id=ScannerId("cap"),
                    findings=(),
                    raw_output="",
                    duration_seconds=0.0,
                )

        registry.register(ConfigCapture(plugin_id="cap"))
        orchestrator.execute_all(fake_ip, configs={ScannerId("other"): PluginConfig()})
        assert received_configs[0] == PluginConfig()

    def test_execution_order_preserved(
        self, registry: InMemoryPluginRegistry, orchestrator: ScannerOrchestrator, fake_ip: Target
    ) -> None:
        order: list[str] = []

        class OrderPlugin(_StubPlugin):
            def scan(self_nonlocal, target, config) -> ScannerResult:
                order.append(self_nonlocal._id)
                return ScannerResult(
                    scanner_id=ScannerId(self_nonlocal._id),
                    findings=(),
                    raw_output="",
                    duration_seconds=0.0,
                )

        registry.register(OrderPlugin(plugin_id="first"))
        registry.register(OrderPlugin(plugin_id="second"))
        registry.register(OrderPlugin(plugin_id="third"))
        orchestrator.execute_all(fake_ip)
        assert order == ["first", "second", "third"]

    def test_empty_registry(
        self, registry: InMemoryPluginRegistry, orchestrator: ScannerOrchestrator, fake_ip: Target
    ) -> None:
        results = orchestrator.execute_all(fake_ip)
        assert results == ()


# ===========================================================================
# scan()
# ===========================================================================


class TestScan:
    def test_returns_flattened_findings(
        self, registry: InMemoryPluginRegistry, orchestrator: ScannerOrchestrator, fake_ip: Target
    ) -> None:
        f1 = _finding("SQLi", Severity.CRITICAL)
        f2 = _finding("XSS", Severity.MEDIUM)
        registry.register(_StubPlugin(plugin_id="nuclei", findings=(f1, f2)))
        findings = orchestrator.scan(fake_ip)
        assert len(findings) == 2
        assert f1 in findings
        assert f2 in findings

    def test_multiple_plugins(
        self, registry: InMemoryPluginRegistry, orchestrator: ScannerOrchestrator, fake_ip: Target
    ) -> None:
        f1 = _finding("SQLi", Severity.CRITICAL)
        f2 = _finding("Open Port", Severity.LOW)
        registry.register(_StubPlugin(plugin_id="nuclei", findings=(f1,)))
        registry.register(_StubPlugin(plugin_id="nmap", findings=(f2,)))
        findings = orchestrator.scan(fake_ip)
        assert len(findings) == 2
        assert f1 in findings
        assert f2 in findings

    def test_empty_findings(
        self, registry: InMemoryPluginRegistry, orchestrator: ScannerOrchestrator, fake_ip: Target
    ) -> None:
        registry.register(_StubPlugin(plugin_id="nuclei"))
        findings = orchestrator.scan(fake_ip)
        assert findings == ()

    def test_empty_registry(
        self, registry: InMemoryPluginRegistry, orchestrator: ScannerOrchestrator, fake_ip: Target
    ) -> None:
        findings = orchestrator.scan(fake_ip)
        assert findings == ()

    def test_returns_tuple(
        self, registry: InMemoryPluginRegistry, orchestrator: ScannerOrchestrator, fake_ip: Target
    ) -> None:
        registry.register(_StubPlugin(plugin_id="nuclei"))
        result = orchestrator.scan(fake_ip)
        assert isinstance(result, tuple)


# ===========================================================================
# compatible_scanners()
# ===========================================================================


class TestCompatibleScanners:
    def test_maps_id_to_display_name(
        self, registry: InMemoryPluginRegistry, orchestrator: ScannerOrchestrator, fake_ip: Target
    ) -> None:
        registry.register(_StubPlugin(plugin_id="nuclei"))
        result = orchestrator.compatible_scanners(fake_ip)
        assert result == {"nuclei": "Stub nuclei"}

    def test_multiple_plugins(
        self, registry: InMemoryPluginRegistry, orchestrator: ScannerOrchestrator, fake_ip: Target
    ) -> None:
        registry.register(_StubPlugin(plugin_id="nuclei"))
        registry.register(_StubPlugin(plugin_id="nmap"))
        result = orchestrator.compatible_scanners(fake_ip)
        assert result == {"nuclei": "Stub nuclei", "nmap": "Stub nmap"}

    def test_empty_registry(
        self, registry: InMemoryPluginRegistry, orchestrator: ScannerOrchestrator, fake_ip: Target
    ) -> None:
        result = orchestrator.compatible_scanners(fake_ip)
        assert result == {}

    def test_matches_what_scan_would_actually_run(
        self, registry: InMemoryPluginRegistry, orchestrator: ScannerOrchestrator, fake_ip: Target
    ) -> None:
        """The whole point of this method: it must reflect exactly what a
        subsequent scan() against the same target would attempt - not an
        independent guess."""
        registry.register(_StubPlugin(plugin_id="nuclei", findings=(_finding(),)))
        registry.register(_StubPlugin(plugin_id="nmap"))

        compatible = orchestrator.compatible_scanners(fake_ip)
        results = orchestrator.execute_all(fake_ip)

        assert set(compatible.keys()) == {str(r.scanner_id) for r in results}

    def test_excludes_incompatible_target_type(
        self, registry: InMemoryPluginRegistry, orchestrator: ScannerOrchestrator
    ) -> None:
        """A plugin declaring NETWORK_RANGE only - the one requirement a
        URL target genuinely cannot satisfy (Phase 2B Task 2: URL now
        provides REACHABLE_HOST too, so the default REACHABLE_HOST-
        declaring _StubPlugin would incorrectly match a URL target here) -
        must resolve to no plugins against a NETWORK target's complement."""
        registry.register(_StubPlugin(plugin_id="nuclei", requirement=ScannerRequirement.NETWORK_RANGE))
        result = orchestrator.compatible_scanners(Target("10.0.0.5", TargetType.IP_ADDRESS))
        assert result == {}


# ===========================================================================
# shutdown()
# ===========================================================================


class TestShutdown:
    def test_shutdown_every_plugin(self, registry: InMemoryPluginRegistry, orchestrator: ScannerOrchestrator) -> None:
        p1 = _StubPlugin(plugin_id="nuclei")
        p2 = _StubPlugin(plugin_id="nmap")
        registry.register(p1)
        registry.register(p2)
        orchestrator.shutdown()
        assert p1.shutdown_called is True
        assert p2.shutdown_called is True

    def test_continue_after_failure(self, registry: InMemoryPluginRegistry, orchestrator: ScannerOrchestrator) -> None:
        p1 = _StubPlugin(plugin_id="bad", raise_on_shutdown=RuntimeError("boom"))
        p2 = _StubPlugin(plugin_id="good")
        registry.register(p1)
        registry.register(p2)
        orchestrator.shutdown()  # should not raise
        assert p2.shutdown_called is True

    def test_unavailable_plugin_handled(
        self, registry: InMemoryPluginRegistry, orchestrator: ScannerOrchestrator
    ) -> None:
        p1 = _StubPlugin(plugin_id="unavail", available=False, availability_reason="missing")
        p2 = _StubPlugin(plugin_id="good")
        registry.register(p1)
        registry.register(p2)
        orchestrator.shutdown()  # should not raise
        assert p1.shutdown_called is False  # skipped
        assert p2.shutdown_called is True

    def test_never_raises(self, registry: InMemoryPluginRegistry, orchestrator: ScannerOrchestrator) -> None:
        p1 = _StubPlugin(plugin_id="a", raise_on_shutdown=RuntimeError("a"))
        p2 = _StubPlugin(plugin_id="b", raise_on_shutdown=ValueError("b"))
        registry.register(p1)
        registry.register(p2)
        orchestrator.shutdown()  # must not raise


# ===========================================================================
# Inherits from ScannerPort
# ===========================================================================


class TestInheritance:
    def test_is_scanner_port(self) -> None:
        assert issubclass(ScannerOrchestrator, ScannerPort)

    def test_is_scanner_executor(self) -> None:
        from kingsec.application.ports.scanner_executor import ScannerExecutor

        assert issubclass(ScannerOrchestrator, ScannerExecutor)

    def test_can_be_assigned_to_scanner_port(self) -> None:
        registry = InMemoryPluginRegistry()
        orch: ScannerPort = ScannerOrchestrator(registry)
        assert isinstance(orch, ScannerPort)

    def test_can_be_assigned_to_scanner_executor(self) -> None:
        from kingsec.application.ports.scanner_executor import ScannerExecutor

        registry = InMemoryPluginRegistry()
        orch: ScannerExecutor = ScannerOrchestrator(registry)
        assert isinstance(orch, ScannerExecutor)


# ===========================================================================
# execute_all(): transient-failure retry
# ===========================================================================


class _FlakyPlugin(_StubPlugin):
    """Fails the first `fail_times` scans with `error`, then succeeds."""

    def __init__(self, *, fail_times: int, error: Exception, **kwargs) -> None:
        super().__init__(**kwargs)
        self._fail_times = fail_times
        self._error = error
        self.scan_calls = 0

    def scan(self, target: Target, config: PluginConfig) -> ScannerResult:
        self.scan_calls += 1
        if self.scan_calls <= self._fail_times:
            raise self._error
        return super().scan(target, config)


def _transient_error() -> ScannerExecutionError:
    return ScannerExecutionError("gobuster exited with code 1")


def _permanent_error() -> ScannerExecutionError:
    return ScannerExecutionError(
        "ffuf aborted: target returns a non-404 response for a nonexistent path",
        transient=False,
    )


def _retry_orchestrator(max_retries: int = 2) -> ScannerOrchestrator:
    return ScannerOrchestrator(
        InMemoryPluginRegistry(),
        retry_settings=OrchestratorSettings(max_retries=max_retries, retry_cooldown_seconds=0),
    )


class TestRetryTransientFailures:
    def test_transient_failure_retried_then_succeeds(self, fake_ip: Target) -> None:
        plugin = _FlakyPlugin(plugin_id="gobuster", fail_times=2, error=_transient_error())
        orch = _retry_orchestrator(max_retries=2)
        orch._registry.register(plugin)
        results = orch.execute_all(fake_ip)
        assert plugin.scan_calls == 3
        assert len(results) == 1

    def test_transient_failure_exhausts_retries(self, fake_ip: Target) -> None:
        plugin = _FlakyPlugin(plugin_id="gobuster", fail_times=99, error=_transient_error())
        orch = _retry_orchestrator(max_retries=2)
        orch._registry.register(plugin)
        results = orch.execute_all(fake_ip)
        assert plugin.scan_calls == 3  # 1 initial + 2 retries
        assert results == ()  # honest failure, nothing fabricated

    def test_permanent_failure_not_retried(self, fake_ip: Target) -> None:
        plugin = _FlakyPlugin(plugin_id="ffuf", fail_times=99, error=_permanent_error())
        orch = _retry_orchestrator(max_retries=2)
        orch._registry.register(plugin)
        results = orch.execute_all(fake_ip)
        assert plugin.scan_calls == 1
        assert results == ()

    def test_retry_disabled_when_max_retries_zero(self, fake_ip: Target) -> None:
        plugin = _FlakyPlugin(plugin_id="gobuster", fail_times=99, error=_transient_error())
        orch = _retry_orchestrator(max_retries=0)
        orch._registry.register(plugin)
        results = orch.execute_all(fake_ip)
        assert plugin.scan_calls == 1
        assert results == ()

    def test_non_execution_error_not_retried(self, fake_ip: Target) -> None:
        plugin = _FlakyPlugin(plugin_id="nmap", fail_times=99, error=RuntimeError("boom"))
        orch = _retry_orchestrator(max_retries=2)
        orch._registry.register(plugin)
        results = orch.execute_all(fake_ip)
        assert plugin.scan_calls == 1
        assert results == ()

    def test_other_plugins_unaffected_by_retry(self, fake_ip: Target) -> None:
        flaky = _FlakyPlugin(plugin_id="gobuster", fail_times=1, error=_transient_error())
        good = _StubPlugin(plugin_id="nuclei", findings=(_finding(),))
        orch = _retry_orchestrator(max_retries=2)
        orch._registry.register(flaky)
        orch._registry.register(good)
        results = orch.execute_all(fake_ip)
        assert flaky.scan_calls == 2
        assert len(results) == 2


# ===========================================================================
# execute_all(): user cancellation
# ===========================================================================
#
# Regression coverage for the defect where cancelling an assessment
# returned 200 OK while scanners kept running: the engine's cancelled flag
# existed, but nothing in the scan path observed it.


class _CountingPlugin(_StubPlugin):
    """Stub plugin that counts scan() invocations."""

    def __init__(self, **kwargs) -> None:
        super().__init__(**kwargs)
        self.scan_calls = 0

    def scan(self, target: Target, config: PluginConfig) -> ScannerResult:
        self.scan_calls += 1
        return super().scan(target, config)


class _SleepPlugin(_CountingPlugin):
    """Runs a real `sleep` through the real runner: exercises the true
    in-flight cancellation path (orchestrator scope -> runner poll loop ->
    process-tree kill) instead of simulating it."""

    def __init__(self, *, sleep_seconds: int = 60, **kwargs) -> None:
        super().__init__(**kwargs)
        self._sleep_seconds = sleep_seconds

    def scan(self, target: Target, config: PluginConfig) -> ScannerResult:
        SubprocessCommandRunner().run(
            ["sleep", str(self._sleep_seconds)], timeout=self._sleep_seconds + 30
        )
        return super().scan(target, config)


def _running_engine(tracking_id: str, plugin_ids: list[str]) -> AssessmentExecutionEngine:
    engine = AssessmentExecutionEngine()
    engine.start_execution(tracking_id, {pid: pid for pid in plugin_ids})
    engine.transition_phase(tracking_id, ExecutionPhase.RUNNING_SCANNERS)
    return engine


def _scanner_state(engine: AssessmentExecutionEngine, tid: str, plugin_id: str):
    state = engine.get_state(tid)
    assert state is not None
    by_id = {s.scanner_id: s for s in state.scanner_progress}
    return by_id[plugin_id]


class TestCancellation:
    def test_cancel_before_dispatch_runs_nothing(self, fake_ip: Target) -> None:
        p1 = _CountingPlugin(plugin_id="p1")
        p2 = _CountingPlugin(plugin_id="p2")
        orch = ScannerOrchestrator(InMemoryPluginRegistry())
        orch._registry.register(p1)
        orch._registry.register(p2)
        engine = _running_engine("assess-1", ["p1", "p2"])
        assert engine.cancel_execution("assess-1") is True

        results = orch.execute_all(
            fake_ip,
            scanner_ids=["p1", "p2"],
            execution_engine=engine,
            tracking_id="assess-1",
        )

        assert results == ()
        assert p1.scan_calls == 0
        assert p2.scan_calls == 0
        # No scanner is left PENDING forever; the phase still says cancelled.
        for pid in ("p1", "p2"):
            progress = _scanner_state(engine, "assess-1", pid)
            assert progress.status.is_terminal
            assert "cancelled by user" in (progress.error or "")
        assert engine.get_state("assess-1").phase == ExecutionPhase.CANCELLED

    def test_in_flight_cancel_kills_scanner_and_stops_dispatch(self, fake_ip: Target) -> None:
        sleeper = _SleepPlugin(plugin_id="sleeper", sleep_seconds=60)
        p2 = _CountingPlugin(plugin_id="p2")
        orch = ScannerOrchestrator(InMemoryPluginRegistry())
        orch._registry.register(sleeper)
        orch._registry.register(p2)
        engine = _running_engine("assess-1", ["sleeper", "p2"])

        outcome: dict[str, object] = {}

        def _run() -> None:
            started = time.monotonic()
            outcome["results"] = orch.execute_all(
                fake_ip,
                scanner_ids=["sleeper", "p2"],
                execution_engine=engine,
                tracking_id="assess-1",
            )
            outcome["elapsed"] = time.monotonic() - started

        thread = threading.Thread(target=_run, daemon=True)
        thread.start()

        # Wait until the sleeper's subprocess is actually running, then cancel.
        deadline = time.monotonic() + 15
        while time.monotonic() < deadline:
            if _scanner_state(engine, "assess-1", "sleeper").status == ScannerRunState.RUNNING:
                break
            time.sleep(0.1)
        assert _scanner_state(engine, "assess-1", "sleeper").status == ScannerRunState.RUNNING
        assert engine.cancel_execution("assess-1") is True

        thread.join(timeout=20)
        assert not thread.is_alive(), "execute_all did not stop after cancel"

        # The 60s sleep died on the ~0.5s poll cadence, not at its timeout.
        assert outcome["elapsed"] < 20, f"cancel took too long: {outcome['elapsed']:.1f}s"
        assert outcome["results"] == ()
        assert p2.scan_calls == 0
        sleeper_progress = _scanner_state(engine, "assess-1", "sleeper")
        assert sleeper_progress.status == ScannerRunState.FAILED
        assert "cancelled" in (sleeper_progress.error or "").lower()

    def test_cancel_during_retry_cooldown_wakes_immediately(self, fake_ip: Target) -> None:
        flaky = _FlakyPlugin(plugin_id="gobuster", fail_times=99, error=_transient_error())
        orch = ScannerOrchestrator(
            InMemoryPluginRegistry(),
            retry_settings=OrchestratorSettings(max_retries=2, retry_cooldown_seconds=30),
        )
        orch._registry.register(flaky)
        engine = _running_engine("assess-1", ["gobuster"])

        outcome: dict[str, object] = {}

        def _run() -> None:
            started = time.monotonic()
            outcome["results"] = orch.execute_all(
                fake_ip,
                scanner_ids=["gobuster"],
                execution_engine=engine,
                tracking_id="assess-1",
            )
            outcome["elapsed"] = time.monotonic() - started

        thread = threading.Thread(target=_run, daemon=True)
        thread.start()

        # Wait for the first attempt to fail, then cancel during the cooldown.
        deadline = time.monotonic() + 15
        while time.monotonic() < deadline and flaky.scan_calls < 1:
            time.sleep(0.05)
        assert flaky.scan_calls == 1
        assert engine.cancel_execution("assess-1") is True

        thread.join(timeout=15)
        assert not thread.is_alive(), "execute_all slept through the cancel"

        # No retry was attempted, and we never waited out the 30s cooldown.
        assert flaky.scan_calls == 1
        assert outcome["elapsed"] < 15, f"cooldown not interrupted: {outcome['elapsed']:.1f}s"
        assert outcome["results"] == ()

    def test_completed_scanners_keep_results_on_cancel(self, fake_ip: Target) -> None:
        p1 = _CountingPlugin(plugin_id="p1", findings=(_finding(),))
        p2 = _CountingPlugin(plugin_id="p2")
        orch = ScannerOrchestrator(InMemoryPluginRegistry())
        orch._registry.register(p1)
        orch._registry.register(p2)
        engine = _running_engine("assess-1", ["p1", "p2"])
        # Cancel lands after p1 finished: p1's real result survives, p2 never runs.
        original_scan = p1.scan

        def _scan_and_cancel(target: Target, config: PluginConfig) -> ScannerResult:
            result = original_scan(target, config)
            engine.cancel_execution("assess-1")
            return result

        p1.scan = _scan_and_cancel  # type: ignore[method-assign]
        results = orch.execute_all(
            fake_ip,
            scanner_ids=["p1", "p2"],
            execution_engine=engine,
            tracking_id="assess-1",
        )
        assert len(results) == 1
        assert p2.scan_calls == 0
        assert _scanner_state(engine, "assess-1", "p1").status == ScannerRunState.SUCCEEDED
