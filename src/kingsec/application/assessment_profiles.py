"""Assessment Profiles, Execution Plans & the Execution Planner.

Application-layer service that defines reusable assessment profiles, validates
target compatibility, checks scanner availability via the Phase 6 discovery
service, and produces execution plans.

No domain entities are modified. No scanner architecture is changed.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any

from kingsec.application.scanner_discovery import ScannerDiscoveryService
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
    """One scanner's status within an execution plan."""

    scanner_id: str
    name: str
    status: str  # "selected" | "skipped" | "unavailable" | "required_unavailable"
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
        scanners=("nmap", "gobuster", "ffuf", "nuclei", "zap"),
        estimated_duration_minutes=60,
        required_scanners=("nmap",),
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
        name="Source Code Review",
        description="Static analysis of source code using Semgrep. Detects security anti-patterns, injection flaws, and hardcoded secrets.",
        supported_target_types=(TargetType.HOSTNAME, TargetType.IP_ADDRESS),
        scanners=("semgrep",),
        estimated_duration_minutes=15,
        required_scanners=("semgrep",),
        tags=("code", "static-analysis", "semgrep"),
    ),
    "container-scan": AssessmentProfile(
        id="container-scan",
        name="Container Assessment",
        description="Vulnerability scanning of container images and filesystems using Trivy. Detects known CVEs in system packages and application dependencies.",
        supported_target_types=(TargetType.HOSTNAME, TargetType.IP_ADDRESS),
        scanners=("trivy",),
        estimated_duration_minutes=10,
        required_scanners=("trivy",),
        tags=("container", "vulnerability", "cve"),
    ),
    "external-footprint": AssessmentProfile(
        id="external-footprint",
        name="External Footprint Mapping",
        description="Discovers the external attack surface using Amass for subdomain enumeration and Nmap for service discovery.",
        supported_target_types=(TargetType.HOSTNAME, TargetType.IP_ADDRESS),
        scanners=("amass", "nmap"),
        estimated_duration_minutes=20,
        required_scanners=("nmap",),
        tags=("footprint", "discovery", "reconnaissance"),
    ),
    "full-assessment": AssessmentProfile(
        id="full-assessment",
        name="Full Assessment",
        description="Runs every available scanner against the target. Maximum coverage: network discovery, vulnerability scanning, web fuzzing, static analysis, and container scanning. Unavailable scanners are automatically skipped.",
        supported_target_types=(
            TargetType.IP_ADDRESS,
            TargetType.HOSTNAME,
            TargetType.URL,
        ),
        scanners=("nmap", "nuclei", "gobuster", "ffuf", "semgrep", "trivy", "amass", "zap", "nikto"),
        estimated_duration_minutes=90,
        required_scanners=(),
        tags=("comprehensive", "maximum-coverage"),
    ),
}


# ---------------------------------------------------------------------------
# Execution Planner
# ---------------------------------------------------------------------------


class ExecutionPlanner:
    """Produces execution plans by matching profiles against targets and scanner health."""

    def __init__(self, discovery: ScannerDiscoveryService | None = None) -> None:
        self._discovery = discovery or ScannerDiscoveryService()
        self._profiles = dict(_DEFAULT_PROFILES)

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
            status = scanner_statuses.get(sid)

            if status is None:
                skipped.append(PlanScannerEntry(
                    scanner_id=sid,
                    name=sid,
                    status="skipped",
                    reason="Unknown scanner",
                ))
                warnings.append(f"Scanner {sid!r} is not recognised by the discovery service.")
                continue

            is_required = sid in profile.required_scanners
            name = status.name

            if status.usable:
                selected.append(PlanScannerEntry(
                    scanner_id=sid,
                    name=name,
                    status="selected",
                ))
            elif status.installed and not status.usable:
                # Installed but missing assets.
                if is_required:
                    unavailable.append(PlanScannerEntry(
                        scanner_id=sid,
                        name=name,
                        status="required_unavailable",
                        reason=status.availability_reason or "Missing required assets",
                    ))
                    warnings.append(f"Required scanner {name!r} is installed but unusable: {status.availability_reason}")
                else:
                    skipped.append(PlanScannerEntry(
                        scanner_id=sid,
                        name=name,
                        status="skipped",
                        reason=status.availability_reason or "Missing assets",
                    ))
                    warnings.append(f"Optional scanner {name!r} skipped: {status.availability_reason}")
            else:
                # Not installed.
                if is_required:
                    unavailable.append(PlanScannerEntry(
                        scanner_id=sid,
                        name=name,
                        status="required_unavailable",
                        reason=f"{name!r} is not installed",
                    ))
                    warnings.append(f"Required scanner {name!r} is not installed. "
                                    f"Hints: {'; '.join(status.install_hints) if status.install_hints else 'Install the scanner'}")
                else:
                    skipped.append(PlanScannerEntry(
                        scanner_id=sid,
                        name=name,
                        status="unavailable",
                        reason=f"{name!r} is not installed",
                    ))

        # If any required scanner is unavailable, the plan cannot proceed.
        can_proceed = len([e for e in unavailable if e.status == "required_unavailable"]) == 0

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
        return {
            "profile_id": plan.profile_id,
            "profile_name": plan.profile_name,
            "target_value": plan.target_value,
            "target_type": plan.target_type.value,
            "selected_scanners": [
                {"scanner_id": s.scanner_id, "name": s.name, "status": s.status, "reason": s.reason}
                for s in plan.selected_scanners
            ],
            "skipped_scanners": [
                {"scanner_id": s.scanner_id, "name": s.name, "status": s.status, "reason": s.reason}
                for s in plan.skipped_scanners
            ],
            "unavailable_scanners": [
                {"scanner_id": s.scanner_id, "name": s.name, "status": s.status, "reason": s.reason}
                for s in plan.unavailable_scanners
            ],
            "warnings": list(plan.warnings),
            "estimated_duration_minutes": plan.estimated_duration_minutes,
            "can_proceed": plan.can_proceed,
        }
