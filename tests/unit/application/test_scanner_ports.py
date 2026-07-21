"""Scanner plugin application ports: abstractness, signatures, and exports."""

from __future__ import annotations

import pytest

from kingsec.application.errors import (
    ApplicationError,
    ScannerConfigError,
    ScannerDuplicateError,
    ScannerPluginError,
    ScannerTimeoutError,
    ScannerUnavailableError,
    ScannerVersionError,
)
from kingsec.application.ports import (
    ScannerExecutor,
    ScannerPluginPort,
    ScannerPluginRegistry,
)

# ===========================================================================
# ScannerPluginPort
# ===========================================================================


class TestScannerPluginPort:
    def test_cannot_instantiate_abstract(self) -> None:
        with pytest.raises(TypeError):
            ScannerPluginPort()  # type: ignore[abstract]

    def test_incomplete_implementation_cannot_instantiate(self) -> None:
        class PartialPlugin(ScannerPluginPort):
            def metadata(self):
                pass

            # missing: capabilities, is_available, scan

        with pytest.raises(TypeError):
            PartialPlugin()  # type: ignore[abstract]

    def test_complete_implementation_can_instantiate(self) -> None:
        from kingsec.domain import (
            OutputFormat,
            PluginAvailability,
            PluginConfig,
            ScanCategory,
            ScannerCapability,
            ScannerId,
            ScannerPluginMetadata,
            ScannerResult,
            Target,
            TargetType,
        )

        class FakePlugin(ScannerPluginPort):
            def metadata(self) -> ScannerPluginMetadata:
                return ScannerPluginMetadata(
                    id=ScannerId("fake"),
                    name="Fake",
                    version="0.0.1",
                    author="Test",
                    description="A fake plugin",
                    api_version="1.0",
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
                return ScannerResult(
                    scanner_id=ScannerId("fake"),
                    findings=(),
                    raw_output="",
                    duration_seconds=0.0,
                )

        plugin = FakePlugin()
        assert isinstance(plugin, ScannerPluginPort)

    def test_health_check_default_calls_is_available(self) -> None:
        from kingsec.application.errors import ScannerUnavailableError
        from kingsec.domain import (
            PluginAvailability,
            ScannerId,
            ScannerPluginMetadata,
        )

        class UnavailablePlugin(ScannerPluginPort):
            def metadata(self) -> ScannerPluginMetadata:
                return ScannerPluginMetadata(
                    id=ScannerId("unavail"),
                    name="Unavailable",
                    version="0.0.1",
                    author="Test",
                    description="Always unavailable",
                    api_version="1.0",
                )

            def capabilities(self):
                return ()

            def is_available(self) -> PluginAvailability:
                return PluginAvailability(
                    available=False, reason="binary not found"
                )

            def scan(self, target, config):
                raise AssertionError("should not be called")

        plugin = UnavailablePlugin()
        with pytest.raises(ScannerUnavailableError, match="binary not found"):
            plugin.health_check()

    def test_health_check_passes_when_available(self) -> None:
        from kingsec.domain import (
            OutputFormat,
            PluginAvailability,
            PluginConfig,
            ScanCategory,
            ScannerCapability,
            ScannerId,
            ScannerPluginMetadata,
            ScannerResult,
            Target,
            TargetType,
        )

        class AvailablePlugin(ScannerPluginPort):
            def metadata(self) -> ScannerPluginMetadata:
                return ScannerPluginMetadata(
                    id=ScannerId("ok"),
                    name="OK",
                    version="0.0.1",
                    author="Test",
                    description="Available",
                    api_version="1.0",
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
                raise AssertionError("should not be called")

        plugin = AvailablePlugin()
        plugin.health_check()  # should not raise

    def test_shutdown_default_is_noop(self) -> None:
        from kingsec.domain import (
            OutputFormat,
            PluginAvailability,
            PluginConfig,
            ScanCategory,
            ScannerCapability,
            ScannerId,
            ScannerPluginMetadata,
            ScannerResult,
            Target,
            TargetType,
        )

        class NoopPlugin(ScannerPluginPort):
            def metadata(self) -> ScannerPluginMetadata:
                return ScannerPluginMetadata(
                    id=ScannerId("noop"),
                    name="Noop",
                    version="0.0.1",
                    author="Test",
                    description="Noop",
                    api_version="1.0",
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
                raise AssertionError("should not be called")

        plugin = NoopPlugin()
        plugin.shutdown()  # should not raise

    def test_has_required_methods(self) -> None:
        methods = {"metadata", "capabilities", "is_available", "scan", "health_check", "shutdown"}
        actual = {m for m in dir(ScannerPluginPort) if not m.startswith("_")}
        assert methods.issubset(actual)


# ===========================================================================
# ScannerPluginRegistry
# ===========================================================================


class TestScannerPluginRegistry:
    def test_cannot_instantiate_abstract(self) -> None:
        with pytest.raises(TypeError):
            ScannerPluginRegistry()  # type: ignore[abstract]

    def test_incomplete_implementation_cannot_instantiate(self) -> None:
        class PartialRegistry(ScannerPluginRegistry):
            def register(self, plugin):
                pass

            # missing: get, resolve, list_all

        with pytest.raises(TypeError):
            PartialRegistry()  # type: ignore[abstract]

    def test_has_required_methods(self) -> None:
        methods = {"register", "get", "resolve", "list_all"}
        actual = {m for m in dir(ScannerPluginRegistry) if not m.startswith("_")}
        assert methods.issubset(actual)


# ===========================================================================
# ScannerExecutor
# ===========================================================================


class TestScannerExecutor:
    def test_cannot_instantiate_abstract(self) -> None:
        with pytest.raises(TypeError):
            ScannerExecutor()  # type: ignore[abstract]

    def test_incomplete_implementation_cannot_instantiate(self) -> None:
        class PartialExecutor(ScannerExecutor):
            def execute(self, plugin, target, config):
                pass

            # missing: execute_all

        with pytest.raises(TypeError):
            PartialExecutor()  # type: ignore[abstract]

    def test_has_required_methods(self) -> None:
        methods = {"execute", "execute_all"}
        actual = {m for m in dir(ScannerExecutor) if not m.startswith("_")}
        assert methods.issubset(actual)


# ===========================================================================
# Error hierarchy
# ===========================================================================


class TestScannerPluginErrors:
    def test_scanner_plugin_error_is_application_error(self) -> None:
        assert issubclass(ScannerPluginError, ApplicationError)

    @pytest.mark.parametrize(
        "exc_cls",
        [
            ScannerUnavailableError,
            ScannerConfigError,
            ScannerVersionError,
            ScannerDuplicateError,
            ScannerTimeoutError,
        ],
    )
    def test_scanner_error_is_scanner_plugin_error(self, exc_cls: type) -> None:
        assert issubclass(exc_cls, ScannerPluginError)

    def test_scanner_unavailable_error_carries_scanner_id(self) -> None:
        exc = ScannerUnavailableError("not found", scanner_id="nuclei")
        assert exc.scanner_id == "nuclei"
        assert str(exc) == "not found"

    def test_scanner_unavailable_error_default_scanner_id_is_none(self) -> None:
        exc = ScannerUnavailableError("not found")
        assert exc.scanner_id is None

    def test_scanner_config_error(self) -> None:
        exc = ScannerConfigError("bad config")
        assert str(exc) == "bad config"

    def test_scanner_version_error(self) -> None:
        exc = ScannerVersionError("incompatible")
        assert str(exc) == "incompatible"

    def test_scanner_duplicate_error(self) -> None:
        exc = ScannerDuplicateError("already registered")
        assert str(exc) == "already registered"

    def test_scanner_timeout_error(self) -> None:
        exc = ScannerTimeoutError("timed out")
        assert str(exc) == "timed out"


# ===========================================================================
# Exports verification
# ===========================================================================


class TestExports:
    def test_ports_exported_from_application(self) -> None:
        import kingsec.application as app

        assert "ScannerPluginPort" in app.__all__
        assert "ScannerPluginRegistry" in app.__all__
        assert "ScannerExecutor" in app.__all__

    def test_errors_exported_from_application(self) -> None:
        import kingsec.application as app

        assert "ScannerPluginError" in app.__all__
        assert "ScannerUnavailableError" in app.__all__
        assert "ScannerConfigError" in app.__all__
        assert "ScannerVersionError" in app.__all__
        assert "ScannerDuplicateError" in app.__all__
        assert "ScannerTimeoutError" in app.__all__

    def test_ports_importable_from_application(self) -> None:
        from kingsec.application import (
            ScannerExecutor,
            ScannerPluginPort,
            ScannerPluginRegistry,
        )

        assert ScannerPluginPort is not None
        assert ScannerPluginRegistry is not None
        assert ScannerExecutor is not None

    def test_errors_importable_from_application(self) -> None:
        from kingsec.application import (
            ScannerConfigError,
            ScannerDuplicateError,
            ScannerPluginError,
            ScannerTimeoutError,
            ScannerUnavailableError,
            ScannerVersionError,
        )

        assert ScannerPluginError is not None
        assert ScannerUnavailableError is not None
        assert ScannerConfigError is not None
        assert ScannerVersionError is not None
        assert ScannerDuplicateError is not None
        assert ScannerTimeoutError is not None

    def test_ports_importable_from_ports_package(self) -> None:
        from kingsec.application.ports import (
            ScannerExecutor,
            ScannerPluginPort,
            ScannerPluginRegistry,
        )

        assert ScannerPluginPort is not None
        assert ScannerPluginRegistry is not None
        assert ScannerExecutor is not None
