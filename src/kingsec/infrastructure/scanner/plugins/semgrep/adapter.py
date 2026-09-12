"""Semgrep scanner plugin adapter.

Wraps the existing ``SemgrepScannerAdapter`` behind the ``ScannerPluginPort``
interface. All subprocess execution, argument building, and JSON parsing are
delegated to the already-tested adapter — this class adds only the metadata,
capability declaration, and availability check that the plugin framework
requires.

Phase 2B Decision 1: NOT WIRED TO ANY PROFILE. Semgrep is a static
source-code analyzer — it genuinely needs a local filesystem path to a
source checkout, not a network-reachable target (IP/hostname/URL), which
is the only kind of target KingSec's current model expresses. Kept
registered and tested so it is ready the moment a real ``repository`` or
``path`` target type exists (see docs/STATUS.md's Phase 2B roadmap item).
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
    Target,
)
from kingsec.infrastructure.scanner.errors import BINARY_ABSENT_USER_MESSAGE

if TYPE_CHECKING:
    from kingsec.infrastructure.config.models import SemgrepSettings
    from kingsec.infrastructure.scanner.runner import CommandRunner
    from kingsec.infrastructure.scanner.semgrep import SemgrepScannerAdapter


class SemgrepPlugin(ScannerPluginPort):
    """Scanner plugin that wraps the Semgrep adapter.

    Delegates scanning entirely to ``SemgrepScannerAdapter``. Adds only the
    metadata and capability declarations that the plugin framework needs
    for registration and resolution.
    """

    def __init__(
        self,
        settings: SemgrepSettings,
        runner: CommandRunner | None = None,
    ) -> None:
        from kingsec.infrastructure.scanner.semgrep import SemgrepScannerAdapter

        self._adapter: SemgrepScannerAdapter = SemgrepScannerAdapter(settings, runner=runner)
        self._settings = settings

    def metadata(self) -> ScannerPluginMetadata:
        """Return the Semgrep plugin identity card."""
        return ScannerPluginMetadata(
            id=ScannerId("semgrep"),
            name="Semgrep",
            version="1.0.0",
            author="KingSec",
            description="Pattern-based static analysis powered by Semgrep",
            api_version="1.0",
        )

    def capabilities(self) -> tuple[ScannerCapability, ...]:
        """Declare Semgrep scanning capabilities."""
        return (
            ScannerCapability(
                requirement=ScannerRequirement.REACHABLE_HOST,
                scan_categories=frozenset({ScanCategory.VULNERABILITY, ScanCategory.INFORMATION}),
                output_format=OutputFormat.STRUCTURED_JSON,
            ),
        )

    def is_available(self) -> PluginAvailability:
        """Check if the Semgrep binary is reachable."""
        binary = self._settings.binary_path
        found = shutil.which(binary) is not None
        return PluginAvailability(
            available=found,
            reason=None if found else BINARY_ABSENT_USER_MESSAGE,
            required_dependencies=(binary,),
        )

    def scan(self, target: Target, config: PluginConfig) -> ScannerResult:
        """Delegate to the existing Semgrep adapter.

        The adapter handles argument building, subprocess execution,
        timeout enforcement, and JSON parsing.
        """
        findings = self._adapter.scan(target)
        return ScannerResult(
            scanner_id=ScannerId("semgrep"),
            findings=tuple(findings),
            raw_output="",
            duration_seconds=0.0,
            scanner_version=None,
        )

    def shutdown(self) -> None:
        """No-op. The adapter owns no disposable resources."""
