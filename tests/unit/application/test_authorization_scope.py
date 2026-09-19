"""effective_scan_surface() and find_covering() (Phase 4, task #626): the
bridge between a scan profile's real scanner capabilities and the grants
covering a target.

effective_scan_surface() is checked against the REAL registry/profile
registry (never a stub) so it can never silently diverge from what
ExecutionPlanner.plan() would actually select.
"""

from __future__ import annotations

from datetime import UTC, datetime

from kingsec.application.assessment_profiles import AssessmentProfile, ExecutionPlanner
from kingsec.application.authorization_scope import effective_scan_surface, find_covering
from kingsec.application.ports.scanner_registry import ScannerPluginRegistry
from kingsec.bootstrap.container import Container
from kingsec.domain import (
    AuthorizationGrant,
    ScannerSurfaceTier,
    Target,
    TargetSpecification,
    TargetSpecificationType,
    TargetType,
)
from kingsec.domain.identifiers import AuthorizationGrantId
from kingsec.infrastructure.config import Settings
from kingsec.infrastructure.scanner.provisioning import register_scanner


def _profile(profile_id: str) -> AssessmentProfile:
    profile = ExecutionPlanner().get_profile(profile_id)
    assert profile is not None, f"profile {profile_id!r} does not exist"
    return profile


def _real_registry() -> ScannerPluginRegistry:
    """The REAL scanner plugin registry, wired exactly as
    infrastructure.scanner.provisioning.register_scanner() does - matches
    the same precedent used throughout Phase 4's own test suite
    (test_surface_tier_derivation.py, test_phase2a_honest_coverage.py)."""
    container = Container()
    register_scanner(container, Settings())
    return container.resolve(ScannerPluginRegistry)  # type: ignore[return-value]


def _grant(
    spec: TargetSpecification,
    *,
    valid_from: datetime = datetime(2026, 1, 1, tzinfo=UTC),
    valid_until: datetime = datetime(2026, 2, 1, tzinfo=UTC),
    revoked_at: datetime | None = None,
) -> AuthorizationGrant:
    return AuthorizationGrant(
        id=AuthorizationGrantId.generate(),
        authorized_by="ciso@example.com",
        authorizing_organization="Example Corp",
        target_specification=spec,
        valid_from=valid_from,
        valid_until=valid_until,
        created_by="admin@kingusecurity.com",
        revoked_at=revoked_at,
    )


# ---------------------------------------------------------------------------
# effective_scan_surface()
# ---------------------------------------------------------------------------


class TestEffectiveScanSurface:
    def test_quick_scan_against_ip_address_is_host_any_port_only(self) -> None:
        """quick-scan's only scanner is nmap - the profile's real,
        registered capability declares HOST_ANY_PORT."""
        registry = _real_registry()
        profile = _profile("quick-scan")
        tiers = effective_scan_surface(profile, registry, TargetType.IP_ADDRESS)
        assert tiers == frozenset({ScannerSurfaceTier.HOST_ANY_PORT})

    def test_web_scan_against_url_includes_nmap_host_any_port(self) -> None:
        """web-scan lists nmap. Its own module comment in
        assessment_profiles.py claims nmap "never" declares URL
        compatibility and is always SKIPPED_INCOMPATIBLE for a URL target
        - empirically false against the real registry today:
        provided_requirements(URL) includes REACHABLE_HOST (target.py),
        nmap's capability requires REACHABLE_HOST, and
        registry.is_compatible(nmap, URL) is True - the exact same check
        ExecutionPlanner.plan() itself uses to decide SKIPPED_INCOMPATIBLE,
        so nmap is actually selected, not skipped. This is precisely the
        kind of gap effective_scan_surface() exists to catch: a grant
        scoped only to a URL would NOT be enough for this profile against
        a URL target, because nmap's HOST_ANY_PORT sweep also runs."""
        registry = _real_registry()
        profile = _profile("web-scan")
        tiers = effective_scan_surface(profile, registry, TargetType.URL)
        assert tiers == frozenset(
            {ScannerSurfaceTier.HOST_ANY_PORT, ScannerSurfaceTier.HOST_PORT_PATH, ScannerSurfaceTier.HOST_PORT_ANY_PATH}
        )

    def test_api_scan_against_url_covers_both_web_tiers(self) -> None:
        """api-scan: ffuf (HOST_PORT_PATH), nuclei + zap (HOST_PORT_ANY_PATH)."""
        registry = _real_registry()
        profile = _profile("api-scan")
        tiers = effective_scan_surface(profile, registry, TargetType.URL)
        assert tiers == frozenset({ScannerSurfaceTier.HOST_PORT_PATH, ScannerSurfaceTier.HOST_PORT_ANY_PATH})

    def test_external_footprint_against_hostname_is_host_any_port_only(self) -> None:
        registry = _real_registry()
        profile = _profile("external-footprint")
        tiers = effective_scan_surface(profile, registry, TargetType.HOSTNAME)
        assert tiers == frozenset({ScannerSurfaceTier.HOST_ANY_PORT})


# ---------------------------------------------------------------------------
# find_covering()
# ---------------------------------------------------------------------------


class TestFindCovering:
    def test_returns_none_for_empty_grants(self) -> None:
        target = Target("203.0.113.5", TargetType.IP_ADDRESS)
        result = find_covering([], target, ScannerSurfaceTier.HOST_ANY_PORT, datetime(2026, 1, 15, tzinfo=UTC))
        assert result is None

    def test_finds_the_covering_grant_among_several(self) -> None:
        target = Target("203.0.113.5", TargetType.IP_ADDRESS)
        unrelated = _grant(TargetSpecification(TargetSpecificationType.IP_ADDRESS, "198.51.100.1"))
        covering = _grant(TargetSpecification(TargetSpecificationType.IP_ADDRESS, "203.0.113.5"))
        result = find_covering(
            [unrelated, covering], target, ScannerSurfaceTier.HOST_ANY_PORT, datetime(2026, 1, 15, tzinfo=UTC)
        )
        assert result is covering

    def test_ignores_a_grant_outside_its_validity_window(self) -> None:
        target = Target("203.0.113.5", TargetType.IP_ADDRESS)
        expired = _grant(
            TargetSpecification(TargetSpecificationType.IP_ADDRESS, "203.0.113.5"),
            valid_from=datetime(2025, 1, 1, tzinfo=UTC),
            valid_until=datetime(2025, 2, 1, tzinfo=UTC),
        )
        result = find_covering(
            [expired], target, ScannerSurfaceTier.HOST_ANY_PORT, datetime(2026, 1, 15, tzinfo=UTC)
        )
        assert result is None

    def test_ignores_a_revoked_grant(self) -> None:
        target = Target("203.0.113.5", TargetType.IP_ADDRESS)
        revoked = _grant(
            TargetSpecification(TargetSpecificationType.IP_ADDRESS, "203.0.113.5"),
            revoked_at=datetime(2026, 1, 10, tzinfo=UTC),
        )
        result = find_covering(
            [revoked], target, ScannerSurfaceTier.HOST_ANY_PORT, datetime(2026, 1, 15, tzinfo=UTC)
        )
        assert result is None

    def test_refuses_a_url_grant_for_a_host_any_port_requirement(self) -> None:
        """Blocking 1: a URL-scoped grant never satisfies a host-wide,
        any-port scan (nmap) - a separate host-level grant is required."""
        target = Target("https://example.com/", TargetType.URL)
        url_grant = _grant(TargetSpecification(TargetSpecificationType.URL_PREFIX, "https://example.com/"))
        result = find_covering(
            [url_grant], target, ScannerSurfaceTier.HOST_ANY_PORT, datetime(2026, 1, 15, tzinfo=UTC)
        )
        assert result is None

    def test_path_scoped_url_grant_covers_a_sibling_path_at_host_port_any_path_tier(self) -> None:
        """The "accidental sufficiency" case: a path-scoped grant still
        satisfies a path-ignorant scanner tier for a sibling path."""
        target = Target("https://example.com/other/admin", TargetType.URL)
        url_grant = _grant(TargetSpecification(TargetSpecificationType.URL_PREFIX, "https://example.com/app/"))
        result = find_covering(
            [url_grant], target, ScannerSurfaceTier.HOST_PORT_ANY_PATH, datetime(2026, 1, 15, tzinfo=UTC)
        )
        assert result is url_grant

    def test_path_scoped_url_grant_does_not_cover_a_sibling_path_at_host_port_path_tier(self) -> None:
        target = Target("https://example.com/other/admin", TargetType.URL)
        url_grant = _grant(TargetSpecification(TargetSpecificationType.URL_PREFIX, "https://example.com/app/"))
        result = find_covering(
            [url_grant], target, ScannerSurfaceTier.HOST_PORT_PATH, datetime(2026, 1, 15, tzinfo=UTC)
        )
        assert result is None
