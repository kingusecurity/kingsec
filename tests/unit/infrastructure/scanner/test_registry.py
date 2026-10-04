"""InMemoryPluginRegistry: registration, lookup, resolution, and list_all."""

from __future__ import annotations

import pytest

from kingsec.application.errors import ScannerDuplicateError, ScannerPluginError
from kingsec.application.ports.scanner_plugin import ScannerPluginPort
from kingsec.domain import (
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
    Target,
    TargetType,
)
from kingsec.infrastructure.scanner.registry import InMemoryPluginRegistry

# ---------------------------------------------------------------------------
# Helpers: fake plugin implementations
# ---------------------------------------------------------------------------


class _FakePlugin(ScannerPluginPort):
    """Minimal ScannerPluginPort for testing. Configurable via constructor."""

    def __init__(
        self,
        *,
        plugin_id: str = "fake",
        name: str = "Fake Scanner",
        requirement: ScannerRequirement | None = None,
        scan_categories: frozenset[ScanCategory] | None = None,
        output_format: OutputFormat = OutputFormat.FINDINGS,
        surface_tier: ScannerSurfaceTier = ScannerSurfaceTier.HOST_PORT_ANY_PATH,
        available: bool = True,
        availability_reason: str | None = None,
    ) -> None:
        self._id = plugin_id
        self._name = name
        self._requirement = requirement or ScannerRequirement.REACHABLE_HOST
        self._scan_categories = scan_categories or frozenset({ScanCategory.VULNERABILITY})
        self._output_format = output_format
        self._surface_tier = surface_tier
        self._available = available
        self._availability_reason = availability_reason

    def metadata(self) -> ScannerPluginMetadata:
        return ScannerPluginMetadata(
            id=ScannerId(self._id),
            name=self._name,
            version="1.0.0",
            author="Test",
            description=f"Fake plugin {self._id}",
            api_version="1.0",
        )

    def capabilities(self) -> tuple[ScannerCapability, ...]:
        return (
            ScannerCapability(
                requirement=self._requirement,
                scan_categories=self._scan_categories,
                output_format=self._output_format,
                surface_tier=self._surface_tier,
            ),
        )

    def is_available(self) -> PluginAvailability:
        return PluginAvailability(
            available=self._available,
            reason=self._availability_reason,
        )

    def scan(self, target: Target, config: PluginConfig) -> ScannerResult:
        return ScannerResult(
            scanner_id=ScannerId(self._id),
            findings=(),
            raw_output="",
            duration_seconds=0.0,
        )


class _MultiCapPlugin(ScannerPluginPort):
    """A plugin with multiple capabilities for testing resolution."""

    def __init__(self, plugin_id: str = "multi") -> None:
        self._id = plugin_id

    def metadata(self) -> ScannerPluginMetadata:
        return ScannerPluginMetadata(
            id=ScannerId(self._id),
            name="Multi Capability",
            version="1.0.0",
            author="Test",
            description="Handles multiple target types",
            api_version="1.0",
        )

    def capabilities(self) -> tuple[ScannerCapability, ...]:
        return (
            ScannerCapability(
                requirement=ScannerRequirement.REACHABLE_HOST,
                scan_categories=frozenset({ScanCategory.VULNERABILITY}),
                output_format=OutputFormat.STRUCTURED_JSON,
                surface_tier=ScannerSurfaceTier.HOST_PORT_ANY_PATH,
            ),
            ScannerCapability(
                requirement=ScannerRequirement.NETWORK_RANGE,
                scan_categories=frozenset({ScanCategory.DISCOVERY}),
                output_format=OutputFormat.RAW_TEXT,
                surface_tier=ScannerSurfaceTier.HOST_ANY_PORT,
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


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


@pytest.fixture
def registry() -> InMemoryPluginRegistry:
    return InMemoryPluginRegistry()


@pytest.fixture
def fake_ip() -> Target:
    return Target("10.0.0.5", TargetType.IP_ADDRESS)


@pytest.fixture
def fake_url() -> Target:
    return Target("https://example.com", TargetType.URL)


@pytest.fixture
def fake_hostname() -> Target:
    return Target("example.com", TargetType.HOSTNAME)


# ===========================================================================
# Registration
# ===========================================================================


class TestRegistration:
    def test_register_one_plugin(self, registry: InMemoryPluginRegistry) -> None:
        plugin = _FakePlugin(plugin_id="nuclei")
        registry.register(plugin)
        assert len(registry.list_all()) == 1

    def test_register_multiple_plugins(self, registry: InMemoryPluginRegistry) -> None:
        registry.register(_FakePlugin(plugin_id="nuclei"))
        registry.register(_FakePlugin(plugin_id="nmap"))
        registry.register(_FakePlugin(plugin_id="nikto"))
        assert len(registry.list_all()) == 3

    def test_duplicate_registration_raises(self, registry: InMemoryPluginRegistry) -> None:
        registry.register(_FakePlugin(plugin_id="nuclei"))
        with pytest.raises(ScannerDuplicateError, match="nuclei"):
            registry.register(_FakePlugin(plugin_id="nuclei"))

    def test_duplicate_different_ids_ok(self, registry: InMemoryPluginRegistry) -> None:
        registry.register(_FakePlugin(plugin_id="nuclei"))
        registry.register(_FakePlugin(plugin_id="nmap"))
        assert len(registry.list_all()) == 2


# ===========================================================================
# Lookup
# ===========================================================================


class TestLookup:
    def test_get_existing_plugin(self, registry: InMemoryPluginRegistry) -> None:
        plugin = _FakePlugin(plugin_id="nuclei")
        registry.register(plugin)
        result = registry.get(ScannerId("nuclei"))
        assert result is plugin

    def test_get_missing_plugin_raises(self, registry: InMemoryPluginRegistry) -> None:
        with pytest.raises(ScannerPluginError, match="nuclei"):
            registry.get(ScannerId("nuclei"))

    def test_get_preserves_identity(self, registry: InMemoryPluginRegistry) -> None:
        plugin = _FakePlugin(plugin_id="nuclei")
        registry.register(plugin)
        assert registry.get(ScannerId("nuclei")) is plugin
        assert registry.get(ScannerId("nuclei")) is registry.get(ScannerId("nuclei"))


# ===========================================================================
# Resolution
# ===========================================================================


class TestResolution:
    def test_target_matches_plugin_capability(self, registry: InMemoryPluginRegistry, fake_ip: Target) -> None:
        registry.register(_FakePlugin(plugin_id="nuclei"))
        result = registry.resolve(fake_ip)
        assert len(result) == 1
        assert result[0].metadata().id == ScannerId("nuclei")

    def test_target_does_not_match_capability(self, registry: InMemoryPluginRegistry, fake_ip: Target) -> None:
        # Phase 2B Task 2: URL now provides REACHABLE_HOST too (that's the
        # feature this task adds), so a REACHABLE_HOST-only plugin no
        # longer demonstrates a non-match against a URL target. NETWORK_RANGE
        # is the one requirement URL genuinely cannot satisfy - use an
        # IP_ADDRESS target (which also lacks NETWORK_RANGE) instead.
        registry.register(_FakePlugin(plugin_id="nuclei", requirement=ScannerRequirement.NETWORK_RANGE))
        result = registry.resolve(fake_ip)
        assert len(result) == 0

    def test_multiple_matching_plugins(self, registry: InMemoryPluginRegistry, fake_ip: Target) -> None:
        registry.register(_FakePlugin(plugin_id="nuclei"))
        registry.register(_FakePlugin(plugin_id="nmap"))
        result = registry.resolve(fake_ip)
        assert len(result) == 2
        ids = {p.metadata().id for p in result}
        assert ids == {ScannerId("nuclei"), ScannerId("nmap")}

    def test_empty_registry(self, registry: InMemoryPluginRegistry, fake_ip: Target) -> None:
        result = registry.resolve(fake_ip)
        assert result == ()

    def test_multi_capability_plugin_matches_multiple_targets(self, registry: InMemoryPluginRegistry) -> None:
        # _MultiCapPlugin declares REACHABLE_HOST (satisfied by IP_ADDRESS,
        # HOSTNAME, and URL) AND NETWORK_RANGE (satisfied by NETWORK) -
        # genuinely multi-capability, matching every target type, the same
        # shape nmap's own real declaration now has (Phase 2B Task 2).
        registry.register(_MultiCapPlugin(plugin_id="multi"))
        ip_result = registry.resolve(Target("10.0.0.5", TargetType.IP_ADDRESS))
        url_result = registry.resolve(Target("https://example.com", TargetType.URL))
        host_result = registry.resolve(Target("example.com", TargetType.HOSTNAME))
        net_result = registry.resolve(Target("10.0.0.0/24", TargetType.NETWORK))
        assert len(ip_result) == 1
        assert len(url_result) == 1
        assert len(host_result) == 1
        assert len(net_result) == 1


# ===========================================================================
# list_all
# ===========================================================================


class TestListAll:
    def test_metadata_returned(self, registry: InMemoryPluginRegistry) -> None:
        registry.register(_FakePlugin(plugin_id="nuclei"))
        result = registry.list_all()
        assert len(result) == 1
        meta, _avail = result[0]
        assert meta.id == ScannerId("nuclei")
        assert meta.name == "Fake Scanner"

    def test_availability_returned(self, registry: InMemoryPluginRegistry) -> None:
        registry.register(_FakePlugin(plugin_id="nuclei", available=True))
        _, avail = registry.list_all()[0]
        assert avail.available is True

    def test_unavailable_plugin_still_listed(self, registry: InMemoryPluginRegistry) -> None:
        registry.register(
            _FakePlugin(
                plugin_id="broken",
                available=False,
                availability_reason="binary not found",
            )
        )
        result = registry.list_all()
        assert len(result) == 1
        meta, avail = result[0]
        assert meta.id == ScannerId("broken")
        assert avail.available is False
        assert avail.reason == "binary not found"

    def test_list_all_multiple(self, registry: InMemoryPluginRegistry) -> None:
        registry.register(_FakePlugin(plugin_id="nuclei"))
        registry.register(_FakePlugin(plugin_id="nmap", available=False, availability_reason="missing"))
        result = registry.list_all()
        assert len(result) == 2
        ids = {meta.id for meta, _ in result}
        assert ids == {ScannerId("nuclei"), ScannerId("nmap")}


# ===========================================================================
# Registry behaviour
# ===========================================================================


class TestRegistryBehaviour:
    def test_preserves_object_identity(self, registry: InMemoryPluginRegistry) -> None:
        plugin = _FakePlugin(plugin_id="nuclei")
        registry.register(plugin)
        assert registry.get(ScannerId("nuclei")) is plugin

    def test_immutable_metadata_respected(self, registry: InMemoryPluginRegistry) -> None:
        plugin = _FakePlugin(plugin_id="nuclei")
        registry.register(plugin)
        meta = plugin.metadata()
        # Metadata is frozen — attempting to mutate raises
        import dataclasses

        with pytest.raises(dataclasses.FrozenInstanceError):
            meta.name = "Changed"  # type: ignore[misc]

    def test_no_mutation_of_plugin_instances(self, registry: InMemoryPluginRegistry) -> None:
        plugin = _FakePlugin(plugin_id="nuclei")
        registry.register(plugin)
        # The registry stores the same object, not a copy
        retrieved = registry.get(ScannerId("nuclei"))
        assert retrieved is plugin

    def test_resolve_returns_new_tuple_each_call(self, registry: InMemoryPluginRegistry) -> None:
        plugin = _FakePlugin(plugin_id="nuclei")
        registry.register(plugin)
        target = Target("10.0.0.5", TargetType.IP_ADDRESS)
        r1 = registry.resolve(target)
        r2 = registry.resolve(target)
        assert r1 == r2
        assert r1 is not r2  # different tuple objects


# ===========================================================================
# Inherits from ScannerPluginRegistry
# ===========================================================================


class TestInheritance:
    def test_is_subclass(self) -> None:
        from kingsec.application.ports.scanner_registry import ScannerPluginRegistry

        assert issubclass(InMemoryPluginRegistry, ScannerPluginRegistry)

    def test_can_be_assigned_to_port_type(self) -> None:
        from kingsec.application.ports.scanner_registry import ScannerPluginRegistry

        registry: ScannerPluginRegistry = InMemoryPluginRegistry()
        assert isinstance(registry, ScannerPluginRegistry)
