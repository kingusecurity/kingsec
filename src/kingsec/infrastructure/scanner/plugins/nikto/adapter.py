"""Nikto scanner plugin adapter.

Wraps the existing ``NiktoScannerAdapter`` behind the ``ScannerPluginPort``
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
    ScannerRequirement,
    ScannerResult,
    ScannerSurfaceTier,
    Target,
)
from kingsec.infrastructure.scanner.errors import BINARY_ABSENT_USER_MESSAGE

if TYPE_CHECKING:
    from kingsec.infrastructure.config.models import NiktoSettings
    from kingsec.infrastructure.scanner.nikto import NiktoScannerAdapter
    from kingsec.infrastructure.scanner.runner import CommandRunner


class NiktoPlugin(ScannerPluginPort):
    """Scanner plugin that wraps the Nikto adapter.

    Delegates scanning entirely to ``NiktoScannerAdapter``. Adds only the
    metadata and capability declarations that the plugin framework needs
    for registration and resolution.
    """

    def __init__(
        self,
        settings: NiktoSettings,
        runner: CommandRunner | None = None,
    ) -> None:
        from kingsec.infrastructure.scanner.nikto import NiktoScannerAdapter

        self._adapter: NiktoScannerAdapter = NiktoScannerAdapter(settings, runner=runner)
        self._settings = settings

    def metadata(self) -> ScannerPluginMetadata:
        """Return the Nikto plugin identity card."""
        return ScannerPluginMetadata(
            id=ScannerId("nikto"),
            name="Nikto Scanner",
            version="1.0.0",
            author="KingSec",
            description="Web server vulnerability scanner powered by Nikto",
            api_version="1.0",
        )

    def capabilities(self) -> tuple[ScannerCapability, ...]:
        """Declare Nikto's scanning capabilities.

        Phase 2B Task 2 Decision 1: one REACHABLE_HOST capability. This
        expands real compatibility to include IP_ADDRESS (previously
        excluded despite the underlying adapter's _parse_target() already
        handling a bare host correctly - see infrastructure/scanner/
        nikto.py). Approved explicitly: "It reflects real adapter
        behaviour."
        """
        return (
            ScannerCapability(
                requirement=ScannerRequirement.REACHABLE_HOST,
                scan_categories=frozenset({ScanCategory.VULNERABILITY}),
                output_format=OutputFormat.RAW_TEXT,
                # Phase 4: verified directly against nikto.py - parses
                # (hostname, port, use_ssl) from the target and scans the
                # web server there; does not respect any path component at
                # all. Host:port, any path.
                surface_tier=ScannerSurfaceTier.HOST_PORT_ANY_PATH,
            ),
        )

    def is_available(self) -> PluginAvailability:
        """Check if the Nikto binary is reachable."""
        binary = self._settings.binary_path
        found = shutil.which(binary) is not None
        return PluginAvailability(
            available=found,
            reason=None if found else BINARY_ABSENT_USER_MESSAGE,
            required_dependencies=(binary,),
        )

    def scan(self, target: Target, config: PluginConfig) -> ScannerResult:
        """Delegate to the existing Nikto adapter.

        The adapter handles argument building, subprocess execution,
        timeout enforcement, and text parsing.
        """
        findings = self._adapter.scan(target)
        return ScannerResult(
            scanner_id=ScannerId("nikto"),
            findings=tuple(findings),
            raw_output="",
            duration_seconds=0.0,
            scanner_version=None,
        )

    def shutdown(self) -> None:
        """No-op. The adapter owns no disposable resources."""
