"""Phase 4: authorization scope enforcement - the bridge between a scan
profile's real scanner capabilities and the grants covering a target.

Two functions used together by CreateAssessment.execute() (Phase 4 task
#627):

    effective_scan_surface()  - every ScannerSurfaceTier a profile's
        scanners could touch for a given target type, derived entirely
        from the REAL registry's own capability declarations - never a
        hand-maintained table (see
        tests/integration/scanner/test_surface_tier_derivation.py, which
        is the required proof those declarations are honest).

    find_covering()  - the first active grant whose specification
        satisfies_tier() a single required tier for a target, or None.
        Pure domain-object manipulation (no persistence, no registry) -
        the candidate grants are supplied by the caller, already loaded
        via AuthorizationGrantRepository.find_active().
"""

from __future__ import annotations

from collections.abc import Iterable
from datetime import datetime

from kingsec.application.assessment_profiles import AssessmentProfile
from kingsec.application.ports.scanner_plugin import ScannerPluginPort
from kingsec.application.ports.scanner_registry import ScannerPluginRegistry
from kingsec.domain import AuthorizationGrant, ScannerId, ScannerSurfaceTier, Target, TargetType, satisfies_tier
from kingsec.domain.scanner import provided_requirements


def _surface_tiers_for_plugins(
    plugins: Iterable[ScannerPluginPort],
    target_type: TargetType,
) -> frozenset[ScannerSurfaceTier]:
    """Return only the capability tiers usable by ``target_type``.

    A plugin may declare several capabilities for different input shapes.
    Being compatible through one capability does not authorize every other
    capability the same plugin exposes.  Filtering by the target's provided
    requirements keeps this derivation identical to registry compatibility
    instead of accidentally broadening it when a plugin grows a second,
    differently-scoped mode.
    """
    provided = provided_requirements(target_type)
    return frozenset(
        capability.surface_tier
        for plugin in plugins
        for capability in plugin.capabilities()
        if capability.requirement in provided
    )


def effective_scan_surface(
    profile: AssessmentProfile,
    registry: ScannerPluginRegistry,
    target_type: TargetType,
) -> frozenset[ScannerSurfaceTier]:
    """Every distinct ScannerSurfaceTier *profile*'s scanners could touch
    against a target of *target_type*.

    Compatibility is decided the same way ExecutionPlanner.plan() already
    decides which scanners run - registry.is_compatible() - so this can
    never silently diverge from what would actually be selected.
    """
    plugins: list[ScannerPluginPort] = []
    for scanner_id in profile.scanners:
        sid = ScannerId(scanner_id)
        if not registry.is_compatible(sid, target_type):
            continue
        plugins.append(registry.get(sid))
    return _surface_tiers_for_plugins(plugins, target_type)


def effective_unprofiled_scan_surface(
    registry: ScannerPluginRegistry,
    target: Target,
) -> frozenset[ScannerSurfaceTier]:
    """Every tier the no-profile execution path will actually touch.

    ``SubmitAssessment`` passes ``scanner_ids=None`` when an assessment has
    no profile.  ``ScannerOrchestrator.execute_all()`` then executes exactly
    ``registry.resolve(target)``: every compatible registered plugin.  Use
    that same resolution here so grant enforcement cannot authorize a
    narrower, imaginary scanner selection.  Scheduled assessments currently
    use this path too because their persisted ``scanner_ids`` are not carried
    into ``Assessment`` execution.
    """
    return _surface_tiers_for_plugins(registry.resolve(target), target.type)


def find_covering(
    grants: Iterable[AuthorizationGrant],
    target: Target,
    required_tier: ScannerSurfaceTier,
    at: datetime,
) -> AuthorizationGrant | None:
    """The first active grant among *grants* whose specification licenses
    a scanner touching *required_tier*'s extent of surface against
    *target*, or None if no grant does.
    """
    for grant in grants:
        if not grant.is_active(at):
            continue
        if satisfies_tier(grant.target_specification, target, required_tier).covered:
            return grant
    return None
