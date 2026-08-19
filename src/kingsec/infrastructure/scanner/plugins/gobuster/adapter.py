"""Gobuster scanner plugin adapter.

Wraps the existing ``GobusterScannerAdapter`` behind the ``ScannerPluginPort``
interface. All subprocess execution, argument building, and text parsing are
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
from kingsec.infrastructure.scanner.errors import BINARY_ABSENT_USER_MESSAGE

if TYPE_CHECKING:
    from kingsec.infrastructure.config.models import GobusterSettings
    from kingsec.infrastructure.scanner.gobuster import GobusterScannerAdapter
    from kingsec.infrastructure.scanner.runner import CommandRunner


class GobusterPlugin(ScannerPluginPort):
    """Scanner plugin that wraps the Gobuster adapter.

    Delegates scanning entirely to ``GobusterScannerAdapter``. Adds only the
    metadata and capability declarations that the plugin framework needs
    for registration and resolution.
    """

    def __init__(
        self,
        settings: GobusterSettings,
        runner: CommandRunner | None = None,
    ) -> None:
        from kingsec.infrastructure.scanner.gobuster import GobusterScannerAdapter

        self._adapter: GobusterScannerAdapter = GobusterScannerAdapter(settings, runner=runner)
        self._settings = settings

    def metadata(self) -> ScannerPluginMetadata:
        """Return the Gobuster plugin identity card."""
        return ScannerPluginMetadata(
            id=ScannerId("gobuster"),
            name="Gobuster Scanner",
            version="1.0.0",
            author="KingSec",
            description="Directory and DNS brute-forcer powered by Gobuster",
            api_version="1.0",
        )

    def capabilities(self) -> tuple[ScannerCapability, ...]:
        """Declare Gobuster's scanning capabilities."""
        return (
            ScannerCapability(
                target_types=frozenset({TargetType.HOSTNAME, TargetType.URL}),
                scan_categories=frozenset({ScanCategory.DISCOVERY}),
                output_format=OutputFormat.RAW_TEXT,
            ),
        )

    def is_available(self) -> PluginAvailability:
        """Check if the Gobuster binary is reachable."""
        binary = self._settings.binary_path
        found = shutil.which(binary) is not None
        return PluginAvailability(
            available=found,
            reason=None if found else BINARY_ABSENT_USER_MESSAGE,
            required_dependencies=(binary,),
        )

    def scan(self, target: Target, config: PluginConfig) -> ScannerResult:
        """Delegate to the existing Gobuster adapter.

        The adapter handles argument building, subprocess execution,
        timeout enforcement, and text parsing.
        """
        findings = self._adapter.scan(target)
        return ScannerResult(
            scanner_id=ScannerId("gobuster"),
            findings=tuple(findings),
            raw_output="",
            duration_seconds=0.0,
            scanner_version=None,
        )

    def shutdown(self) -> None:
        """No-op. The adapter owns no disposable resources."""
