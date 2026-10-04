"""ffuf scanner plugin adapter.

Wraps the existing ``FfufScannerAdapter`` behind the ``ScannerPluginPort``
interface. All subprocess execution, argument building, and JSON parsing are
delegated to the already-tested adapter — this class adds only the metadata,
capability declaration, and availability check that the plugin framework
requires.
"""

from __future__ import annotations

import shutil
from collections.abc import Callable
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
        *,
        wildcard_probe: Callable[[str, float], bool] | None = None,
    ) -> None:
        from kingsec.infrastructure.scanner.ffuf import FfufScannerAdapter

        adapter_kwargs = {} if wildcard_probe is None else {"wildcard_probe": wildcard_probe}
        self._adapter: FfufScannerAdapter = FfufScannerAdapter(settings, runner=runner, **adapter_kwargs)
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
        """Declare ffuf's scanning capabilities.

        Phase 2B Decision 4: URL only, not HOSTNAME. The underlying
        implementation (infrastructure/scanner/ffuf.py's _build_args())
        passes target.value directly as the -u base URL with no scheme
        handling - a bare HOSTNAME target would produce an invalid,
        scheme-less URL. Rather than silently assume http:// (a guess
        that would produce quietly wrong results against an HTTPS-only
        target - a redirect, a refused connection, or worse, fuzzing the
        wrong protocol entirely), require the caller to supply a real URL
        with an explicit scheme.
        """
        return (
            ScannerCapability(
                requirement=ScannerRequirement.HTTP_BASE_URL,
                scan_categories=frozenset({ScanCategory.DISCOVERY, ScanCategory.VULNERABILITY}),
                output_format=OutputFormat.STRUCTURED_JSON,
                # Phase 4: verified directly against
                # ffuf.py:_build_args() - f"{base_url}/FUZZ" fuzzes UNDER
                # the given path, never a sibling. Host:port:path.
                surface_tier=ScannerSurfaceTier.HOST_PORT_PATH,
            ),
        )

    def is_available(self) -> PluginAvailability:
        """Check if the ffuf binary is reachable."""
        binary = self._settings.binary_path
        found = shutil.which(binary) is not None
        return PluginAvailability(
            available=found,
            reason=None if found else BINARY_ABSENT_USER_MESSAGE,
            required_dependencies=(binary,),
        )

    def scan(self, target: Target, config: PluginConfig) -> ScannerResult:
        """Delegate to the existing ffuf adapter.

        The adapter handles argument building, subprocess execution,
        timeout enforcement, and JSON parsing.

        Phase 2B-c Priority 3: rate_limit_description is computed via the
        same resolve_rate_limit_description() the adapter's own
        _build_args() call reads from - not a second, independent guess -
        so what's recorded here can never drift from what actually ran.
        """
        from kingsec.infrastructure.scanner.ffuf import resolve_rate_limit_description

        findings = self._adapter.scan(target)
        return ScannerResult(
            scanner_id=ScannerId("ffuf"),
            findings=tuple(findings),
            raw_output="",
            duration_seconds=0.0,
            scanner_version=None,
            rate_limit_description=resolve_rate_limit_description(self._settings),
        )

    def shutdown(self) -> None:
        """No-op. The adapter owns no disposable resources."""
