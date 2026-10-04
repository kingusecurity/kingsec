"""Nmap scanner plugin adapter.

Wraps the existing ``NmapScannerAdapter`` behind the ``ScannerPluginPort``
interface. All subprocess execution, argument building, and XML parsing are
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
    from kingsec.infrastructure.config.models import NmapSettings
    from kingsec.infrastructure.scanner.nmap import NmapScannerAdapter
    from kingsec.infrastructure.scanner.runner import CommandRunner


class NmapPlugin(ScannerPluginPort):
    """Scanner plugin that wraps the Nmap adapter.

    Delegates scanning entirely to ``NmapScannerAdapter``. Adds only the
    metadata and capability declarations that the plugin framework needs
    for registration and resolution.
    """

    def __init__(
        self,
        settings: NmapSettings,
        runner: CommandRunner | None = None,
    ) -> None:
        from kingsec.infrastructure.scanner.nmap import NmapScannerAdapter

        self._adapter: NmapScannerAdapter = NmapScannerAdapter(settings, runner=runner)
        self._settings = settings

    def metadata(self) -> ScannerPluginMetadata:
        """Return the Nmap plugin identity card."""
        return ScannerPluginMetadata(
            id=ScannerId("nmap"),
            name="Nmap Scanner",
            version="1.0.0",
            author="KingSec",
            description="Network port scanner and service detector powered by Nmap",
            api_version="1.0",
        )

    def capabilities(self) -> tuple[ScannerCapability, ...]:
        """Declare Nmap's scanning capabilities.

        Phase 2B Task 2: two capability entries - nmap can satisfy either
        a reachable host (IP_ADDRESS, HOSTNAME, or a URL's decomposed host)
        or a network range (NETWORK/CIDR). Declaring both, rather than one
        combined capability, keeps a CIDR target from ever being treated as
        a single reachable host or vice versa.
        """
        return (
            ScannerCapability(
                requirement=ScannerRequirement.REACHABLE_HOST,
                scan_categories=frozenset({ScanCategory.DISCOVERY, ScanCategory.CONFIGURATION}),
                output_format=OutputFormat.RAW_TEXT,
                # Phase 4: verified directly against
                # nmap.py:_scan_url_two_invocations() - a URL target's
                # sweep invocation carries no port restriction at all,
                # independent of the target's own port. Non-URL targets
                # get the same unrestricted single invocation. Sweeps the
                # whole host, any port.
                surface_tier=ScannerSurfaceTier.HOST_ANY_PORT,
            ),
            ScannerCapability(
                requirement=ScannerRequirement.NETWORK_RANGE,
                scan_categories=frozenset({ScanCategory.DISCOVERY, ScanCategory.CONFIGURATION}),
                output_format=OutputFormat.RAW_TEXT,
                surface_tier=ScannerSurfaceTier.HOST_ANY_PORT,
            ),
        )

    def is_available(self) -> PluginAvailability:
        """Check if the Nmap binary is reachable."""
        binary = self._settings.binary_path
        found = shutil.which(binary) is not None
        return PluginAvailability(
            available=found,
            reason=None if found else BINARY_ABSENT_USER_MESSAGE,
            required_dependencies=(binary,),
        )

    def scan(self, target: Target, config: PluginConfig) -> ScannerResult:
        """Delegate to the existing Nmap adapter.

        The adapter handles argument building, subprocess execution,
        timeout enforcement, and XML parsing.

        Phase 2B Task 2 Decision 4c: port_specification is computed via
        the same resolve_port_specification() the adapter's own
        _build_args() calls to build the real invocation - not a second,
        independent guess - so what's recorded here can never drift from
        what nmap actually scanned.
        """
        from kingsec.infrastructure.scanner.nmap import (
            resolve_port_override_warning,
            resolve_port_specification,
        )

        findings = self._adapter.scan(target)
        override_warning = resolve_port_override_warning(target, self._settings)
        warnings = tuple(w for w in (override_warning,) if w is not None) + self._adapter.last_scan_warnings()
        return ScannerResult(
            scanner_id=ScannerId("nmap"),
            findings=tuple(findings),
            raw_output="",
            duration_seconds=0.0,
            scanner_version=None,
            port_specification=resolve_port_specification(target, self._settings),
            warnings=warnings,
        )

    def shutdown(self) -> None:
        """No-op. The adapter owns no disposable resources."""
