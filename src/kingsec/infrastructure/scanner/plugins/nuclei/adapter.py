"""Nuclei scanner plugin adapter.

Wraps the existing ``NucleiScannerAdapter`` behind the ``ScannerPluginPort``
interface. All subprocess execution, argument building, and JSONL parsing are
delegated to the already-tested adapter — this class adds only the metadata,
capability declaration, and availability check that the plugin framework
requires.

Zero behavioral change: the existing adapter is the single source of truth
for how Nuclei is invoked.
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
from kingsec.infrastructure.scanner.errors import BINARY_ABSENT_USER_MESSAGE

if TYPE_CHECKING:
    from kingsec.infrastructure.config.models import ScannerSettings
    from kingsec.infrastructure.scanner.nuclei import NucleiScannerAdapter
    from kingsec.infrastructure.scanner.runner import CommandRunner


class NucleiPlugin(ScannerPluginPort):
    """Scanner plugin that wraps the existing Nuclei adapter.

    Delegates scanning entirely to ``NucleiScannerAdapter``. Adds only the
    metadata and capability declarations that the plugin framework needs
    for registration and resolution.
    """

    def __init__(
        self,
        settings: ScannerSettings,
        runner: CommandRunner | None = None,
    ) -> None:
        from kingsec.infrastructure.scanner.nuclei import NucleiScannerAdapter

        self._adapter: NucleiScannerAdapter = NucleiScannerAdapter(settings, runner=runner)
        self._settings = settings

    def metadata(self) -> ScannerPluginMetadata:
        """Return the Nuclei plugin identity card."""
        return ScannerPluginMetadata(
            id=ScannerId("nuclei"),
            name="Nuclei Scanner",
            version="1.0.0",
            author="KingSec",
            description="Template-based vulnerability scanner powered by Nuclei",
            api_version="1.0",
        )

    def capabilities(self) -> tuple[ScannerCapability, ...]:
        """Declare Nuclei's scanning capabilities."""
        return (
            ScannerCapability(
                target_types=frozenset({TargetType.IP_ADDRESS, TargetType.HOSTNAME, TargetType.URL}),
                scan_categories=frozenset({ScanCategory.VULNERABILITY}),
                output_format=OutputFormat.STRUCTURED_JSON,
            ),
        )

    def is_available(self) -> PluginAvailability:
        """Check if the Nuclei binary is reachable."""
        binary = self._settings.binary_path
        found = shutil.which(binary) is not None
        return PluginAvailability(
            available=found,
            reason=None if found else BINARY_ABSENT_USER_MESSAGE,
            required_dependencies=(binary,),
        )

    def scan(self, target: Target, config: PluginConfig) -> ScannerResult:
        """Delegate to the existing Nuclei adapter.

        The adapter already handles argument building, subprocess execution,
        timeout enforcement, and JSONL parsing. This method wraps the result
        into a ``ScannerResult``.
        """
        findings = self._adapter.scan(target)
        return ScannerResult(
            scanner_id=ScannerId("nuclei"),
            findings=tuple(findings),
            raw_output="",
            duration_seconds=0.0,
            scanner_version=None,
        )

    def shutdown(self) -> None:
        """No-op. The adapter owns no disposable resources."""
