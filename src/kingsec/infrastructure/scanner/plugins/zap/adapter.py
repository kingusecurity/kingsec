"""OWASP ZAP scanner plugin adapter.

Wraps the existing ``ZapScannerAdapter`` behind the ``ScannerPluginPort``
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
    PluginAvailability,
    PluginConfig,
    ScannerCapability,
    ScannerId,
    ScannerPluginMetadata,
    ScannerResult,
    ScanCategory,
    OutputFormat,
    Target,
    TargetType,
)

if TYPE_CHECKING:
    from kingsec.infrastructure.config.models import ZapSettings
    from kingsec.infrastructure.scanner.zap import ZapScannerAdapter
    from kingsec.infrastructure.scanner.runner import CommandRunner


class ZapPlugin(ScannerPluginPort):
    """Scanner plugin that wraps the OWASP ZAP adapter.

    Delegates scanning entirely to ``ZapScannerAdapter``. Adds only the
    metadata and capability declarations that the plugin framework needs
    for registration and resolution.
    """

    def __init__(
        self,
        settings: "ZapSettings",
        runner: "CommandRunner | None" = None,
    ) -> None:
        from ...zap import ZapScannerAdapter

        self._adapter: ZapScannerAdapter = ZapScannerAdapter(settings, runner=runner)
        self._settings = settings

    def metadata(self) -> ScannerPluginMetadata:
        """Return the ZAP plugin identity card."""
        return ScannerPluginMetadata(
            id=ScannerId("zap"),
            name="OWASP ZAP",
            version="1.0.0",
            author="KingSec",
            description="Web application vulnerability scanner powered by OWASP ZAP",
            api_version="1.0",
        )

    def capabilities(self) -> tuple[ScannerCapability, ...]:
        """Declare ZAP scanning capabilities."""
        return (
            ScannerCapability(
                target_types=frozenset({TargetType.URL}),
                scan_categories=frozenset({ScanCategory.VULNERABILITY}),
                output_format=OutputFormat.STRUCTURED_JSON,
            ),
        )

    def is_available(self) -> PluginAvailability:
        """Check if the ZAP binary is reachable."""
        binary = self._settings.binary_path
        found = shutil.which(binary) is not None
        return PluginAvailability(
            available=found,
            reason=None if found else f"zap binary not found: {binary!r}",
            required_dependencies=(binary,),
        )

    def scan(self, target: Target, config: PluginConfig) -> ScannerResult:
        """Delegate to the existing ZAP adapter.

        The adapter handles argument building, subprocess execution,
        timeout enforcement, and JSON parsing.
        """
        findings = self._adapter.scan(target)
        return ScannerResult(
            scanner_id=ScannerId("zap"),
            findings=tuple(findings),
            raw_output="",
            duration_seconds=0.0,
            scanner_version=None,
        )

    def shutdown(self) -> None:
        """No-op. The adapter owns no disposable resources."""
