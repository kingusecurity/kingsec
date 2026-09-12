"""ScannerOrchestrator: execute, execute_all, scan, and shutdown."""

from __future__ import annotations

import pytest

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
    Severity,
    Target,
    TargetType,
)
from kingsec.infrastructure.scanner.orchestrator import ScannerOrchestrator
from kingsec.infrastructure.scanner.registry import InMemoryPluginRegistry

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
