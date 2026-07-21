"""ffuf scanner plugin adapter.

Wraps the existing ``FfufScannerAdapter`` behind the ``ScannerPluginPort``
interface. All subprocess execution, argument building, and JSON parsing are
delegated to the already-tested adapter — this class adds only the metadata,
capability declaration, and availability check that the plugin framework
requires.
"""

from __future__ import annotations

import shutil
from typing import TYPE_CHECKING

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
    Target,
    TargetType,
)

if TYPE_CHECKING:
    from kingsec.infrastructure.config.models import FfufSettings
    from kingsec.infrastructure.scanner.ffuf import FfufScannerAdapter
    from kingsec.infrastructure.scanner.runner import CommandRunner


class FfufPlugin(ScannerPluginPort):
    """Scanner plugin that wraps the ffuf adapter.

    Delegates scanning entirely to ``FfufScannerAdapter``. Adds only the
    metadata and capability declarations that the plugin framework needs
    for registration and resolution.
    """

    def __init__(
        self,
        settings: FfufSettings,
        runner: CommandRunner | None = None,
    ) -> None:
        from kingsec.infrastructure.scanner.ffuf import FfufScannerAdapter

        self._adapter: FfufScannerAdapter = FfufScannerAdapter(settings, runner=runner)
        self._settings = settings

    def metadata(self) -> ScannerPluginMetadata:
        """Return the ffuf plugin identity card."""
        return ScannerPluginMetadata(
            id=ScannerId("ffuf"),
            name="ffuf Scanner",
            version="1.0.0",
            author="KingSec",
            description="Web fuzzer for directory and parameter discovery powered by ffuf",
            api_version="1.0",
        )

    def capabilities(self) -> tuple[ScannerCapability, ...]:
        """Declare ffuf's scanning capabilities."""
        return (
            ScannerCapability(
                target_types=frozenset({TargetType.HOSTNAME, TargetType.URL}),
                scan_categories=frozenset({ScanCategory.DISCOVERY, ScanCategory.VULNERABILITY}),
                output_format=OutputFormat.STRUCTURED_JSON,
            ),
        )

    def is_available(self) -> PluginAvailability:
        """Check if the ffuf binary is reachable."""
        binary = self._settings.binary_path
        found = shutil.which(binary) is not None
        return PluginAvailability(
            available=found,
            reason=None if found else f"ffuf binary not found: {binary!r}",
            required_dependencies=(binary,),
        )

    def scan(self, target: Target, config: PluginConfig) -> ScannerResult:
        """Delegate to the existing ffuf adapter.

        The adapter handles argument building, subprocess execution,
        timeout enforcement, and JSON parsing.
        """
        findings = self._adapter.scan(target)
        return ScannerResult(
            scanner_id=ScannerId("ffuf"),
            findings=tuple(findings),
            raw_output="",
            duration_seconds=0.0,
            scanner_version=None,
        )

    def shutdown(self) -> None:
        """No-op. The adapter owns no disposable resources."""
