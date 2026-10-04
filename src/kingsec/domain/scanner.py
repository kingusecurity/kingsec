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


class ScannerSurfaceTier(Enum):
    """What EXTENT of surface a scanner actually touches given a target -
    not what target types it accepts (that's ScannerRequirement), but how
    far its own invocation reaches once it runs.

    Phase 4 (authorization scope enforcement): derived from each plugin's
    own capability declaration, never a hand-maintained table elsewhere -
    a parallel table is exactly how Blocking 1 arose in the first place
    (nmap's Phase 2B two-invocation URL design widened its real surface
    without anything re-checking what "in scope" meant against it).

    HOST_ANY_PORT: sweeps the entire host, independent of any port the
        target itself specifies (nmap: verified directly against
        nmap.py's _scan_url_two_invocations(), which runs a sweep
        invocation with no port restriction at all, plus a second
        invocation for the target's own explicit port).
    HOST_PORT_ANY_PATH: touches host:port only, but does not respect any
        path the target specifies - the tool's own crawling/template
        logic can reach any path on that port (nikto, nuclei, zap - each
        verified directly against its own _build_args()/equivalent; none
        pass a path-restricting flag, and each is documented or observed
        to range beyond whatever path was given).
    HOST_PORT_PATH: touches host:port, and respects the target's own path
        as a base - never ranges to a sibling path (ffuf, gobuster -
        verified directly: both literally append their fuzz/brute-force
        probe under the given path, e.g. ffuf's f"{base_url}/FUZZ").
    """

    HOST_ANY_PORT = "host_any_port"
    HOST_PORT_ANY_PATH = "host_port_any_path"
    HOST_PORT_PATH = "host_port_path"


class ScannerRequirement(Enum):
    """What a scanner NEEDS a target to provide, independent of TargetType.

    Phase 2B Task 2: compatibility is "can this target satisfy this
    scanner's requirement," not "is this target's literal enum value in
    this scanner's allowed set." See provided_requirements() below for
    what each TargetType can provide, and
    infrastructure/scanner/registry.py's is_compatible() for how the two
    sides are matched.

    REGISTRABLE_DOMAIN is intentionally not a member yet - it needs a
    registrable_domain TargetType first (Phase 2B Task 1's amass roadmap
    item, still Phase 4 work).
    """

    REACHABLE_HOST = "reachable_host"  # a resolvable host; port optional
    HTTP_BASE_URL = "http_base_url"    # scheme + host + port, ready for an HTTP request
    NETWORK_RANGE = "network_range"    # a CIDR block


def provided_requirements(target_type: TargetType) -> frozenset[ScannerRequirement]:
    """What a target of this type can provide to a scanner.

    Pure, total function - every TargetType has an entry. IP_ADDRESS and
    HOSTNAME deliberately do NOT provide HTTP_BASE_URL: neither carries a
    scheme, and synthesizing "http://<value>" would be exactly the silent
    scheme-guess Phase 2B Task 1 Decision 4 already rejected for ffuf and
    gobuster - this function extends that same rule rather than reopening
    it. URL provides both REACHABLE_HOST and HTTP_BASE_URL: a scanner that
    only needs a reachable host (nmap, nuclei, nikto) can be satisfied by a
    URL just as well as by a bare IP_ADDRESS/HOSTNAME - decompose_url()
    (domain/target.py) is what makes that host actually available.
    """
    mapping: dict[TargetType, frozenset[ScannerRequirement]] = {
        TargetType.IP_ADDRESS: frozenset({ScannerRequirement.REACHABLE_HOST}),
        TargetType.HOSTNAME: frozenset({ScannerRequirement.REACHABLE_HOST}),
        TargetType.URL: frozenset({ScannerRequirement.REACHABLE_HOST, ScannerRequirement.HTTP_BASE_URL}),
        TargetType.NETWORK: frozenset({ScannerRequirement.NETWORK_RANGE}),
    }
    return mapping[target_type]


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

    A plugin declares one or more capabilities (e.g. nmap declares two: one
    needing REACHABLE_HOST, one needing NETWORK_RANGE). The registry uses
    ``requirement`` together with ``provided_requirements(target_type)`` to
    decide compatibility - see infrastructure/scanner/registry.py's
    ``is_compatible()``. Phase 2B Task 2: replaced the previous
    ``target_types: frozenset[TargetType]`` field with a single
    ``requirement`` so there is exactly one source of truth for what a
    scanner needs - a scanner declaring both a requirement AND an
    independent target_types set could drift between the two, which is the
    exact class of bug Phase 2A eliminated once already between the
    planner and the orchestrator.
    """

    requirement: ScannerRequirement
    scan_categories: frozenset[ScanCategory]
    output_format: OutputFormat
    # Phase 4: which extent of surface this scanner actually touches given
    # a target - the single source of truth effective_scan_surface()
    # reads, never a parallel table. Required (no default) so a newly
    # added scanner cannot be registered without its author having made
    # this an explicit decision.
    surface_tier: ScannerSurfaceTier

    def __post_init__(self) -> None:
        if not isinstance(self.requirement, ScannerRequirement):
            raise InvariantViolation(f"ScannerCapability requirement must be a ScannerRequirement: {self.requirement!r}")
        if not isinstance(self.scan_categories, frozenset) or not self.scan_categories:
            raise InvariantViolation("ScannerCapability scan_categories must be a non-empty frozenset of ScanCategory")
        for sc in self.scan_categories:
            if not isinstance(sc, ScanCategory):
                raise InvariantViolation(f"ScannerCapability scan_categories contains non-ScanCategory: {sc!r}")
        if not isinstance(self.output_format, OutputFormat):
            raise InvariantViolation("ScannerCapability output_format must be an OutputFormat")
        if not isinstance(self.surface_tier, ScannerSurfaceTier):
            raise InvariantViolation(f"ScannerCapability surface_tier must be a ScannerSurfaceTier: {self.surface_tier!r}")


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
    # Phase 2B Task 2 Decision 4: the exact nmap -p value used this run
    # (e.g. "18080,1-1000"), for Task 4's port-range disclosure work. Only
    # nmap populates this; every other scanner leaves it None. Deliberately
    # narrow - not a generic "scan parameters" bag - see
    # infrastructure/scanner/nmap.py's resolve_port_specification().
    port_specification: str | None = None
    scanner_version: str | None = None
    warnings: tuple[str, ...] = ()
    # Phase 2B-c Priority 3: what rate limiting actually applied this run,
    # in the scanner's own terms (e.g. "40 requests/second (ffuf -rate)").
    # Only ffuf/gobuster populate this; every other scanner leaves it None.
    # Deliberately narrow, same precedent as port_specification above - see
    # infrastructure/scanner/ffuf.py's resolve_rate_limit_description().
    rate_limit_description: str | None = None

    def __post_init__(self) -> None:
        if not isinstance(self.scanner_id, ScannerId):
            raise InvariantViolation("scanner_id must be a ScannerId")
        if not isinstance(self.findings, tuple):
            raise InvariantViolation("findings must be a tuple")
        if self.duration_seconds < 0:
            raise InvariantViolation(f"duration_seconds must be non-negative, got {self.duration_seconds}")
