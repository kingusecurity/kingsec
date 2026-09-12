"""Trivy scanner plugin adapter.

Wraps the existing ``TrivyScannerAdapter`` behind the ``ScannerPluginPort``
interface. All subprocess execution, argument building, and JSON parsing are
delegated to the already-tested adapter — this class adds only the metadata,
capability declaration, and availability check that the plugin framework
requires.

Phase 2B Decision 1: NOT WIRED TO ANY PROFILE. Trivy scans container
images, filesystems, and git repos — it genuinely needs an image
reference, local filesystem path, or repo URL, not a network-reachable
target (IP/hostname/URL), which is the only kind of target KingSec's
current model expresses. Kept registered and tested so it is ready the
moment a real ``image`` or ``path`` target type exists (see
docs/STATUS.md's Phase 2B roadmap item).
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
    from kingsec.infrastructure.config.models import TrivySettings
    from kingsec.infrastructure.scanner.runner import CommandRunner
    from kingsec.infrastructure.scanner.trivy import TrivyScannerAdapter


class TrivyPlugin(ScannerPluginPort):
    """Scanner plugin that wraps the Trivy adapter.

    Delegates scanning entirely to ``TrivyScannerAdapter``. Adds only the
    metadata and capability declarations that the plugin framework needs
    for registration and resolution.
    """

    def __init__(
        self,
        settings: TrivySettings,
        runner: CommandRunner | None = None,
    ) -> None:
        from kingsec.infrastructure.scanner.trivy import TrivyScannerAdapter

        self._adapter: TrivyScannerAdapter = TrivyScannerAdapter(settings, runner=runner)
        self._settings = settings

    def metadata(self) -> ScannerPluginMetadata:
        """Return the Trivy plugin identity card."""
        return ScannerPluginMetadata(
            id=ScannerId("trivy"),
            name="Trivy Scanner",
            version="1.0.0",
            author="KingSec",
            description="Vulnerability and misconfiguration scanner powered by Trivy",
            api_version="1.0",
        )

    def capabilities(self) -> tuple[ScannerCapability, ...]:
        """Declare Trivy scanning capabilities."""
        return (
            ScannerCapability(
                requirement=ScannerRequirement.REACHABLE_HOST,
                scan_categories=frozenset({ScanCategory.VULNERABILITY, ScanCategory.CONFIGURATION}),
                output_format=OutputFormat.STRUCTURED_JSON,
            ),
        )

    def is_available(self) -> PluginAvailability:
        """Check if the Trivy binary is reachable."""
        binary = self._settings.binary_path
        found = shutil.which(binary) is not None
        return PluginAvailability(
            available=found,
            reason=None if found else BINARY_ABSENT_USER_MESSAGE,
            required_dependencies=(binary,),
        )

    def scan(self, target: Target, config: PluginConfig) -> ScannerResult:
        """Delegate to the existing Trivy adapter.

        The adapter handles argument building, subprocess execution,
        timeout enforcement, and JSON parsing.
        """
        findings = self._adapter.scan(target)
        return ScannerResult(
            scanner_id=ScannerId("trivy"),
            findings=tuple(findings),
            raw_output="",
            duration_seconds=0.0,
            scanner_version=None,
        )

    def shutdown(self) -> None:
        """No-op. The adapter owns no disposable resources."""
