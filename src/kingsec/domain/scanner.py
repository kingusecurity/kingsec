"""Scanner plugin domain concepts.

Defines the value objects and enumerations that describe scanner plugins, their
capabilities, configuration, and results. These are the *vocabulary* the rest of
the system uses to talk about scanners — no behaviour, no side effects, just
pure data with structural invariants.

Why a separate module instead of extending ``enums.py`` or ``evidence.py``?
    Scanner plugins are a distinct bounded context within the domain. Keeping
    their concepts together makes the boundary explicit and avoids bloating
    existing modules with unrelated concerns.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from enum import Enum

from ._validation import ensure_non_empty
from .errors import InvariantViolation
from .finding import Finding
from .target import TargetType

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

_SCANNER_ID_PATTERN = re.compile(r"^[a-z0-9]+(?:-[a-z0-9]+)*$")
_API_VERSION_PATTERN = re.compile(r"^\d+\.\d+$")
_SEMVER_PATTERN = re.compile(r"^\d+\.\d+\.\d+$")


# ---------------------------------------------------------------------------
# Enums
# ---------------------------------------------------------------------------


class ScanCategory(Enum):
    """The kind of security analysis a scanner performs.

    A single scanner may declare multiple categories (e.g. an scanner that
    does both vulnerability detection and service discovery).
    """

    VULNERABILITY = "vulnerability"
    DISCOVERY = "discovery"
    CONFIGURATION = "configuration"
    COMPLIANCE = "compliance"
    INFORMATION = "information"


class OutputFormat(Enum):
    """How a plugin delivers its results.

    The orchestrator uses this to decide whether to invoke a parser or accept
    domain objects directly.
    """

    FINDINGS = "findings"
    RAW_TEXT = "raw_text"
    STRUCTURED_JSON = "structured_json"


# ---------------------------------------------------------------------------
# Value objects
# ---------------------------------------------------------------------------


@dataclass(frozen=True, slots=True)
class ScannerId:
    """Typed, immutable identity for a scanner plugin.

    Format: lowercase alphanumeric with hyphens (e.g. ``"nuclei"``,
    ``"owasp-zap"``).  An empty or blank string is rejected.
    """

    value: str

    def __post_init__(self) -> None:
        ensure_non_empty(self.value, "ScannerId")
        if not _SCANNER_ID_PATTERN.match(self.value):
            raise InvariantViolation("ScannerId must contain only lowercase letters, digits, and hyphens")

    def __str__(self) -> str:
        return self.value


@dataclass(frozen=True, slots=True)
class ScannerPluginMetadata:
    """Declarative identity card for a scanner plugin.

    Immutable once constructed. All fields are validated — a plugin that
    cannot describe itself cleanly cannot be registered.
    """

    id: ScannerId
    name: str
    version: str
    author: str
    description: str
    api_version: str

    def __post_init__(self) -> None:
        if not isinstance(self.id, ScannerId):
            raise InvariantViolation("id must be a ScannerId")
        ensure_non_empty(self.name, "ScannerPluginMetadata name")
        ensure_non_empty(self.author, "ScannerPluginMetadata author")
        ensure_non_empty(self.description, "ScannerPluginMetadata description")
        if not _SEMVER_PATTERN.match(self.version):
            raise InvariantViolation("ScannerPluginMetadata version must be SemVer (e.g. '1.0.0')")
        if not _API_VERSION_PATTERN.match(self.api_version):
            raise InvariantViolation("ScannerPluginMetadata api_version must be 'major.minor' (e.g. '1.0')")


@dataclass(frozen=True, slots=True)
class ScannerCapability:
    """One capability a scanner plugin provides.

    A plugin declares one or more capabilities. The orchestrator uses these
    to decide which plugins to invoke for a given target.
    """

    target_types: frozenset[TargetType]
    scan_categories: frozenset[ScanCategory]
    output_format: OutputFormat

    def __post_init__(self) -> None:
        if not isinstance(self.target_types, frozenset) or not self.target_types:
            raise InvariantViolation("ScannerCapability target_types must be a non-empty frozenset of TargetType")
        for tt in self.target_types:
            if not isinstance(tt, TargetType):
                raise InvariantViolation(f"ScannerCapability target_types contains non-TargetType: {tt!r}")
        if not isinstance(self.scan_categories, frozenset) or not self.scan_categories:
            raise InvariantViolation("ScannerCapability scan_categories must be a non-empty frozenset of ScanCategory")
        for sc in self.scan_categories:
            if not isinstance(sc, ScanCategory):
                raise InvariantViolation(f"ScannerCapability scan_categories contains non-ScanCategory: {sc!r}")
        if not isinstance(self.output_format, OutputFormat):
            raise InvariantViolation("ScannerCapability output_format must be an OutputFormat")


@dataclass(frozen=True, slots=True)
class PluginConfig:
    """Scanner-specific configuration.

    Opaque at the domain level: the domain does not know what keys a
    particular scanner expects. Values must be JSON-primitive types so
    configuration can be serialised and stored.
    """

    settings: dict[str, str | int | float | bool | None] = field(default_factory=dict)

    def __post_init__(self) -> None:
        for key, value in self.settings.items():
            if not isinstance(key, str) or not key.strip():
                raise InvariantViolation("PluginConfig keys must be non-empty strings")
            if value is not None and not isinstance(value, str | int | float | bool):
                raise InvariantViolation(
                    f"PluginConfig value for {key!r} must be a primitive type, got {type(value).__name__}"
                )


@dataclass(frozen=True, slots=True)
class PluginAvailability:
    """Whether a plugin can execute right now."""

    available: bool
    reason: str | None = None
    required_dependencies: tuple[str, ...] = ()

    def __post_init__(self) -> None:
        if not self.available and self.reason is None:
            raise InvariantViolation("PluginAvailability with available=False must provide a reason")
        for dep in self.required_dependencies:
            if not isinstance(dep, str) or not dep.strip():
                raise InvariantViolation("PluginAvailability required_dependencies must be non-empty strings")


@dataclass(frozen=True, slots=True)
class ScannerResult:
    """Normalized output from a single plugin scan.

    Every plugin produces this structure regardless of the underlying tool.
    The orchestrator merges results from multiple plugins.
    """

    scanner_id: ScannerId
    findings: tuple[Finding, ...]
    raw_output: str
    duration_seconds: float
    scanner_version: str | None = None
    warnings: tuple[str, ...] = ()

    def __post_init__(self) -> None:
        if not isinstance(self.scanner_id, ScannerId):
            raise InvariantViolation("scanner_id must be a ScannerId")
        if not isinstance(self.findings, tuple):
            raise InvariantViolation("findings must be a tuple")
        if self.duration_seconds < 0:
            raise InvariantViolation(f"duration_seconds must be non-negative, got {self.duration_seconds}")
