"""Assessment Profiles, Execution Plans & the Execution Planner.

Application-layer service that defines reusable assessment profiles, validates
target compatibility, checks scanner availability via the Phase 6 discovery
service, and produces execution plans.

No domain entities are modified. No scanner architecture is changed.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any

from kingsec.application.ports.scanner_registry import ScannerPluginRegistry
from kingsec.application.scanner_discovery import ScannerDiscoveryService
from kingsec.domain import ScannerId
from kingsec.domain.enums import ScannerRunState
from kingsec.domain.target import TargetType

# ---------------------------------------------------------------------------
# Value objects
# ---------------------------------------------------------------------------


@dataclass(frozen=True, slots=True)
class AssessmentProfile:
    """A reusable assessment profile that selects scanners by intent."""

    id: str
    name: str
    description: str
    supported_target_types: tuple[TargetType, ...]
    scanners: tuple[str, ...]  # scanner_ids in execution order
    estimated_duration_minutes: int
    required_scanners: tuple[str, ...] = ()
    tags: tuple[str, ...] = ()


@dataclass(frozen=True, slots=True)
class PlanScannerEntry:
    """One scanner's decision within an execution plan.

    Phase 2A Correction 2b: ``plan()`` produces exactly one of these for
    EVERY scanner in the profile — never a partial list. ``selected=True``
    means the orchestrator will invoke it; ``selected=False`` always
    carries a ``skip_state`` (one of ``ScannerRunState``'s SKIPPED_*
    members) explaining precisely why, in the same unified vocabulary the
    execution tracker uses (Correction 4 — decided in this one place, not
    per-plugin).
    """

    scanner_id: str
    name: str
    selected: bool
    skip_state: ScannerRunState | None = None
    reason: str = ""


@dataclass(frozen=True, slots=True)
class ExecutionPlan:
    """The result of planning an assessment against a profile."""

    profile_id: str
    profile_name: str
    target_value: str
    target_type: TargetType
    selected_scanners: tuple[PlanScannerEntry, ...]
    skipped_scanners: tuple[PlanScannerEntry, ...]
    unavailable_scanners: tuple[PlanScannerEntry, ...]
    warnings: tuple[str, ...]
    estimated_duration_minutes: int
    can_proceed: bool


# ---------------------------------------------------------------------------
# Default profiles
# ---------------------------------------------------------------------------

_DEFAULT_PROFILES: dict[str, AssessmentProfile] = {
    "quick-scan": AssessmentProfile(
        id="quick-scan",
        name="Quick Host Scan",
        description="A fast, low-impact scan of a single host. Runs Nmap for open ports and service detection. Ideal for a quick health check.",
        supported_target_types=(TargetType.IP_ADDRESS, TargetType.HOSTNAME),
        scanners=("nmap",),
        estimated_duration_minutes=5,
        required_scanners=("nmap",),
        tags=("fast", "lightweight", "discovery"),
    ),
    "network-scan": AssessmentProfile(
        id="network-scan",
        name="Network Assessment",
        description="Scans a network range for live hosts, open ports, and known vulnerabilities. Combines Nmap discovery with Nuclei vulnerability checks.",
        supported_target_types=(TargetType.NETWORK, TargetType.IP_ADDRESS, TargetType.HOSTNAME),
        scanners=("nmap", "nuclei"),
        estimated_duration_minutes=30,
        required_scanners=("nmap",),
        tags=("network", "vulnerability", "discovery"),
    ),
    "web-scan": AssessmentProfile(
        id="web-scan",
        name="Web Application Scan",
        description="Comprehensive web application security assessment. Discovers endpoints with Gobuster and FFUF, then scans for vulnerabilities with Nuclei and OWASP ZAP.",
        supported_target_types=(TargetType.URL,),
        # nmap stays in the scanner list (Phase 2A migration review): a URL
        # target still has a real host/port, and dropping nmap entirely
        # would hide a real coverage gap rather than reporting it. It is
        # NOT required, because nmap's registered capabilities never
        # include TargetType.URL (infrastructure/scanner/plugins/nmap/
        # adapter.py) - making it required here made this profile
        # structurally unable to ever proceed, for any URL target, which
        # TestProfileRequiredScannersAreTargetTypeCompatible now catches
        # for every profile. It is scheduled, correctly reported as
        # SKIPPED_INCOMPATIBLE with a plain-English reason ("not
        # applicable to a URL target"), and counted honestly as a
        # coverage gap (COMPLETED_WITH_GAPS) - never silently dropped.
        # Phase 2B: the real fix is deriving a host/port from the URL so
        # nmap CAN run against it (e.g. http://127.0.0.1:18080) - keeping
        # nmap listed-but-skipped here leaves room for that later.
        scanners=("nmap", "gobuster", "ffuf", "nuclei", "zap"),
        estimated_duration_minutes=60,
        required_scanners=(),
        tags=("web", "vulnerability", "comprehensive"),
    ),
    "api-scan": AssessmentProfile(
        id="api-scan",
        name="API Assessment",
        description="Security assessment of REST/HTTP APIs. Performs endpoint discovery with FFUF, then vulnerability scanning with Nuclei and OWASP ZAP.",
        supported_target_types=(TargetType.URL,),
        scanners=("ffuf", "nuclei", "zap"),
        estimated_duration_minutes=45,
        required_scanners=(),
        tags=("api", "vulnerability"),
    ),
    "code-review": AssessmentProfile(
        id="code-review",
        name="Source Code Assessment",
        description="Scans an absolute source path visible to the KingSec server. Semgrep performs static analysis, while Trivy scans the filesystem for vulnerable dependencies and misconfigurations.",
        supported_target_types=(TargetType.SOURCE_PATH,),
        scanners=("semgrep", "trivy"),
        estimated_duration_minutes=20,
        required_scanners=("semgrep", "trivy"),
        tags=("code", "static-analysis", "dependencies"),
    ),
    "container-scan": AssessmentProfile(
        id="container-scan",
        name="Container Image Assessment",
        description="Scans an OCI/Docker container image reference with Trivy in image mode for known vulnerabilities and misconfigurations.",
        supported_target_types=(TargetType.CONTAINER_IMAGE,),
        scanners=("trivy",),
        estimated_duration_minutes=10,
        required_scanners=("trivy",),
        tags=("container", "vulnerability", "cve"),
    ),
    "domain-enumeration": AssessmentProfile(
        id="domain-enumeration",
        name="Domain Enumeration",
        description="Enumerates subdomains for an explicitly authorized DNS domain with OWASP Amass in passive mode. May query third-party DNS and certificate-transparency sources.",
        supported_target_types=(TargetType.DOMAIN,),
        scanners=("amass",),
        estimated_duration_minutes=15,
        required_scanners=("amass",),
        tags=("domain", "discovery", "reconnaissance"),
    ),
    "external-footprint": AssessmentProfile(
        id="external-footprint",
        name="External Footprint Mapping",
        description="Discovers the external attack surface using Nmap for service discovery.",
        supported_target_types=(TargetType.HOSTNAME, TargetType.IP_ADDRESS),
        # Domain-wide discovery remains separate: it needs the explicit
        # DOMAIN target and grant used by domain-enumeration above, never a
        # generic host/IP target that happens to resemble a public domain.
        scanners=("nmap",),
        estimated_duration_minutes=15,
        required_scanners=("nmap",),
        tags=("footprint", "discovery", "reconnaissance"),
    ),
    "full-assessment": AssessmentProfile(
        id="full-assessment",
        name="Full Assessment",
        description="Runs every available network scanner against the target. Maximum coverage: network discovery, vulnerability scanning, and web fuzzing. Unavailable scanners are automatically skipped.",
        supported_target_types=(
            TargetType.IP_ADDRESS,
            TargetType.HOSTNAME,
            TargetType.URL,
        ),
        # This remains a network-target profile. Source paths, container
        # images, and domain enumeration each have a purpose-built profile
        # above so their scanners are never applied to a lookalike string.
        scanners=("nmap", "nuclei", "gobuster", "ffuf", "zap", "nikto"),
        estimated_duration_minutes=60,
        required_scanners=(),
        tags=("comprehensive", "maximum-coverage"),
    ),
}


# ---------------------------------------------------------------------------
# Execution Planner
# ---------------------------------------------------------------------------


class ExecutionPlanner:
    """Produces execution plans by matching profiles against targets and scanner health.

    Phase 2A Correction 2a: takes a ``ScannerPluginRegistry`` so it can
    check per-scanner target-type compatibility via the registry's own
    ``is_compatible()`` — the exact same logic ``ScannerOrchestrator``
    uses to decide what it will actually execute. This is the single
    source of truth the orchestrator and planner previously disagreed on
    (the Run #4 reference-case root cause): the planner now decides
    compatibility, and the orchestrator (Correction 2c) trusts that
    decision completely instead of re-deriving it.

    ``registry`` is optional only so existing unit tests that construct
    an ``ExecutionPlanner`` without one keep working for pure
    duration/profile-lookup tests; any planner used in a real
    compatibility decision needs a real registry, and ``plan()`` treats a
    missing registry as "no scanner is compatible" (fails closed, never
    silently assumes compatibility).
    """

    def __init__(
        self,
        discovery: ScannerDiscoveryService | None = None,
        registry: ScannerPluginRegistry | None = None,
    ) -> None:
        self._discovery = discovery or ScannerDiscoveryService()
        self._registry = registry
        self._profiles = dict(_DEFAULT_PROFILES)

    @property
    def discovery(self) -> ScannerDiscoveryService:
        """The exact ScannerDiscoveryService this planner decides with.

        Read-only access for callers (Task 3a's ``kingsec doctor``) that
        must report the same binary/asset status the planner itself acts
        on - never a second, independently-constructed ScannerDiscoveryService
        that could silently drift out of sync with this one.
        """
        return self._discovery

    @property
    def registry(self) -> ScannerPluginRegistry | None:
        """The exact ScannerPluginRegistry this planner checks compatibility
        with (see plan()'s own docstring) - same rationale as discovery above."""
        return self._registry

    # ── Profile queries ─────────────────────────────────────────────────

    def list_profiles(self) -> tuple[AssessmentProfile, ...]:
        """Return all registered profiles."""
        return tuple(self._profiles.values())

    def get_profile(self, profile_id: str) -> AssessmentProfile | None:
        """Look up a profile by id."""
        return self._profiles.get(profile_id)

    def get_profiles_for_target_type(self, target_type: TargetType) -> tuple[AssessmentProfile, ...]:
        """Return profiles compatible with the given target type."""
        return tuple(
            p for p in self._profiles.values() if target_type in p.supported_target_types
        )

    # ── Planning ────────────────────────────────────────────────────────

    def plan(
        self,
        profile_id: str,
        target_value: str,
        target_type: TargetType,
    ) -> ExecutionPlan:
        """Produce an execution plan for the given profile and target.

        Args:
            profile_id: The profile to plan against.
            target_value: The target string (hostname, IP, URL).
            target_type: The type of the target.

        Returns:
            An ExecutionPlan with scanner selections, warnings, and
            a ``can_proceed`` flag.

        Raises:
            ValueError: If the profile is not found.
        """
        profile = self.get_profile(profile_id)
        if profile is None:
            raise ValueError(f"Unknown profile: {profile_id!r}")

        # Check target compatibility.
        if target_type not in profile.supported_target_types:
            return ExecutionPlan(
                profile_id=profile_id,
                profile_name=profile.name,
                target_value=target_value,
                target_type=target_type,
                selected_scanners=(),
                skipped_scanners=(),
                unavailable_scanners=(),
                warnings=(f"Target type {target_type.value} is not supported by profile {profile.name!r}. "
                          f"Supported types: {', '.join(t.value for t in profile.supported_target_types)}",),
                estimated_duration_minutes=0,
                can_proceed=False,
            )

        # Get scanner health for all known scanners.
        scanner_statuses = {
            s.scanner_id: s for s in self._discovery.get_all_statuses()
        }

        selected: list[PlanScannerEntry] = []
        skipped: list[PlanScannerEntry] = []
        unavailable: list[PlanScannerEntry] = []
        warnings: list[str] = []

        for sid in profile.scanners:
            is_required = sid in profile.required_scanners
            status = scanner_statuses.get(sid)
            name = status.name if status is not None else sid

            # Decision order, Phase 2A Correction 2:
            # 1. target-type compatibility (moved here from the
            #    orchestrator — the single source of truth, via the same
            #    registry.is_compatible() the orchestrator itself defers
            #    to; never re-derived independently again)
            # 2. is the scanner even known to discovery
            # 3. binary installed
            # 4. required assets present
            # Every branch appends to exactly one bucket and every
            # scanner in profile.scanners is covered — no scanner is ever
            # left undecided.
            if self._registry is not None and not self._registry.is_compatible(ScannerId(sid), target_type):
                entry = PlanScannerEntry(
                    scanner_id=sid,
                    name=name,
                    selected=False,
                    skip_state=ScannerRunState.SKIPPED_INCOMPATIBLE,
                    reason=f"{name!r} does not support target type {target_type.value!r}",
                )
                if is_required:
                    unavailable.append(entry)
                    warnings.append(f"Required scanner {name!r} does not support target type {target_type.value!r}.")
                else:
                    skipped.append(entry)
                    warnings.append(f"Optional scanner {name!r} skipped: does not support target type {target_type.value!r}.")
                continue

            if status is None:
                entry = PlanScannerEntry(
                    scanner_id=sid,
                    name=sid,
                    selected=False,
                    skip_state=ScannerRunState.SKIPPED_BINARY_MISSING,
                    reason="Unknown scanner",
                )
                if is_required:
                    unavailable.append(entry)
                    warnings.append(f"Required scanner {sid!r} is not recognised by the discovery service.")
                else:
                    skipped.append(entry)
                    warnings.append(f"Scanner {sid!r} is not recognised by the discovery service.")
                continue

            if status.usable:
                selected.append(PlanScannerEntry(
                    scanner_id=sid,
                    name=name,
                    selected=True,
                ))
            elif status.installed and not status.usable:
                # Installed but missing a required asset (Correction 4:
                # same SKIPPED_ASSET_MISSING state regardless of which
                # scanner/asset — decided here, in one place, not
                # per-plugin).
                entry = PlanScannerEntry(
                    scanner_id=sid,
                    name=name,
                    selected=False,
                    skip_state=ScannerRunState.SKIPPED_ASSET_MISSING,
                    reason=status.availability_reason or "Missing required assets",
                )
                if is_required:
                    unavailable.append(entry)
                    warnings.append(f"Required scanner {name!r} is installed but unusable: {status.availability_reason}")
                else:
                    skipped.append(entry)
                    warnings.append(f"Optional scanner {name!r} skipped: {status.availability_reason}")
            else:
                # Not installed.
                entry = PlanScannerEntry(
                    scanner_id=sid,
                    name=name,
                    selected=False,
                    skip_state=ScannerRunState.SKIPPED_BINARY_MISSING,
                    reason=f"{name!r} is not installed",
                )
                if is_required:
                    unavailable.append(entry)
                    warnings.append(f"Required scanner {name!r} is not installed. "
                                    f"Hints: {'; '.join(status.install_hints) if status.install_hints else 'Install the scanner'}")
                else:
                    skipped.append(entry)

        # If any required scanner was not selected, the plan cannot proceed
        # — regardless of which of the skip reasons above caused it.
        can_proceed = len(unavailable) == 0

        # Adjust duration estimate based on selected scanners.
        total_duration = sum(
            self._scanner_duration(sid)
            for sid in profile.scanners
            if sid in {e.scanner_id for e in selected}
        )
        estimated = max(total_duration, 1)

        return ExecutionPlan(
            profile_id=profile_id,
            profile_name=profile.name,
            target_value=target_value,
            target_type=target_type,
            selected_scanners=tuple(selected),
            skipped_scanners=tuple(skipped),
            unavailable_scanners=tuple(unavailable),
            warnings=tuple(warnings),
            estimated_duration_minutes=estimated,
            can_proceed=can_proceed,
        )

    @staticmethod
    def _scanner_duration(scanner_id: str) -> int:
        """Baseline per-scanner duration estimate in minutes."""
        estimates: dict[str, int] = {
            "nmap": 5,
            "nuclei": 15,
            "nikto": 20,
            "ffuf": 15,
            "gobuster": 10,
            "trivy": 10,
            "semgrep": 10,
            "amass": 15,
            "zap": 30,
        }
        return estimates.get(scanner_id, 10)

    def profile_to_dict(self, profile: AssessmentProfile) -> dict[str, Any]:
        """Convert a profile to a JSON-safe dict."""
        return {
            "id": profile.id,
            "name": profile.name,
            "description": profile.description,
            "supported_target_types": [t.value for t in profile.supported_target_types],
            "scanners": list(profile.scanners),
            "estimated_duration_minutes": profile.estimated_duration_minutes,
            "required_scanners": list(profile.required_scanners),
            "tags": list(profile.tags),
        }

    def plan_to_dict(self, plan: ExecutionPlan) -> dict[str, Any]:
        """Convert a plan to a JSON-safe dict."""

        def entry_dict(s: PlanScannerEntry) -> dict[str, Any]:
            return {
                "scanner_id": s.scanner_id,
                "name": s.name,
                "selected": s.selected,
                "skip_state": s.skip_state.value if s.skip_state is not None else None,
                "reason": s.reason,
            }

        return {
            "profile_id": plan.profile_id,
            "profile_name": plan.profile_name,
            "target_value": plan.target_value,
            "target_type": plan.target_type.value,
            "selected_scanners": [entry_dict(s) for s in plan.selected_scanners],
            "skipped_scanners": [entry_dict(s) for s in plan.skipped_scanners],
            "unavailable_scanners": [entry_dict(s) for s in plan.unavailable_scanners],
            "warnings": list(plan.warnings),
            "estimated_duration_minutes": plan.estimated_duration_minutes,
            "can_proceed": plan.can_proceed,
        }
