"""AuthorizationGrant aggregate: TargetSpecification, validity window,
covers_target() (strict), and satisfies_tier() (tier-aware, Blocking 1).

Phase 4 (authorization scope enforcement), approved implementation order
item 7 (target-matching decisions) plus Blocking 1/2 from the redesign
round: CIDR-vs-CIDR via subnet_of(), mixed IPv4/IPv6 refusal, and the
tier-aware "accidental sufficiency" behaviour for path-ignorant scanners.
"""

from __future__ import annotations

from datetime import datetime

import pytest
from tests.unit.domain.conftest import utc

from kingsec.domain import (
    AuthorizationGrant,
    InvariantViolation,
    ScannerSurfaceTier,
    ScopeCheckOutcome,
    Target,
    TargetSpecification,
    TargetSpecificationType,
    TargetType,
    covers_target,
    satisfies_tier,
)
from kingsec.domain.identifiers import AuthorizationGrantId


def _grant_id() -> AuthorizationGrantId:
    return AuthorizationGrantId.generate()


def spec(type_: TargetSpecificationType, value: str) -> TargetSpecification:
    return TargetSpecification(type=type_, value=value)


def target(value: str, type_: TargetType) -> Target:
    return Target(value, type_)


# ---------------------------------------------------------------------------
# TargetSpecification validation
# ---------------------------------------------------------------------------


class TestTargetSpecificationValidation:
    def test_accepts_ip_address(self) -> None:
        spec(TargetSpecificationType.IP_ADDRESS, "203.0.113.5")

    def test_accepts_network(self) -> None:
        spec(TargetSpecificationType.NETWORK, "203.0.113.0/24")

    def test_accepts_hostname(self) -> None:
        spec(TargetSpecificationType.HOSTNAME, "api.example.com")

    def test_accepts_wildcard_hostname(self) -> None:
        spec(TargetSpecificationType.WILDCARD_HOSTNAME, "*.example.com")

    def test_accepts_url_prefix(self) -> None:
        spec(TargetSpecificationType.URL_PREFIX, "https://example.com/app/")

    def test_rejects_invalid_type(self) -> None:
        with pytest.raises(InvariantViolation):
            TargetSpecification(type="ip_address", value="203.0.113.5")  # type: ignore[arg-type]

    def test_rejects_empty_value(self) -> None:
        with pytest.raises(InvariantViolation):
            spec(TargetSpecificationType.IP_ADDRESS, "")

    def test_rejects_malformed_ip_address(self) -> None:
        with pytest.raises(InvariantViolation):
            spec(TargetSpecificationType.IP_ADDRESS, "not-an-ip")

    def test_rejects_malformed_network(self) -> None:
        with pytest.raises(InvariantViolation):
            spec(TargetSpecificationType.NETWORK, "203.0.113.0/99")

    def test_rejects_malformed_hostname(self) -> None:
        with pytest.raises(InvariantViolation):
            spec(TargetSpecificationType.HOSTNAME, "-bad-.example.com")

    def test_wildcard_hostname_must_start_with_star_dot(self) -> None:
        with pytest.raises(InvariantViolation):
            spec(TargetSpecificationType.WILDCARD_HOSTNAME, "example.com")

    def test_wildcard_hostname_rejects_malformed_suffix(self) -> None:
        with pytest.raises(InvariantViolation):
            spec(TargetSpecificationType.WILDCARD_HOSTNAME, "*.-bad-.com")

    def test_rejects_url_prefix_without_scheme(self) -> None:
        with pytest.raises(InvariantViolation):
            spec(TargetSpecificationType.URL_PREFIX, "example.com/app")


# ---------------------------------------------------------------------------
# AuthorizationGrant validation and is_active()
# ---------------------------------------------------------------------------


class TestAuthorizationGrantValidation:
    def _valid_kwargs(self) -> dict:
        return dict(
            id=_grant_id(),
            authorized_by="ciso@example.com",
            authorizing_organization="Example Corp",
            target_specification=spec(TargetSpecificationType.IP_ADDRESS, "203.0.113.5"),
            valid_from=utc(2026, 1, 1),
            valid_until=utc(2026, 2, 1),
            created_by="admin@kingusecurity.com",
        )

    def test_accepts_valid_grant(self) -> None:
        AuthorizationGrant(**self._valid_kwargs())

    def test_rejects_invalid_id_type(self) -> None:
        kwargs = self._valid_kwargs()
        kwargs["id"] = "not-an-id"
        with pytest.raises(InvariantViolation):
            AuthorizationGrant(**kwargs)

    def test_rejects_empty_authorized_by(self) -> None:
        kwargs = self._valid_kwargs()
        kwargs["authorized_by"] = ""
        with pytest.raises(InvariantViolation):
            AuthorizationGrant(**kwargs)

    def test_rejects_empty_authorizing_organization(self) -> None:
        kwargs = self._valid_kwargs()
        kwargs["authorizing_organization"] = ""
        with pytest.raises(InvariantViolation):
            AuthorizationGrant(**kwargs)

    def test_rejects_invalid_target_specification_type(self) -> None:
        kwargs = self._valid_kwargs()
        kwargs["target_specification"] = "203.0.113.5"
        with pytest.raises(InvariantViolation):
            AuthorizationGrant(**kwargs)

    def test_rejects_naive_valid_from(self) -> None:
        kwargs = self._valid_kwargs()
        kwargs["valid_from"] = datetime(2026, 1, 1)  # naive
        with pytest.raises(InvariantViolation):
            AuthorizationGrant(**kwargs)

    def test_rejects_naive_valid_until(self) -> None:
        kwargs = self._valid_kwargs()
        kwargs["valid_until"] = datetime(2026, 2, 1)  # naive
        with pytest.raises(InvariantViolation):
            AuthorizationGrant(**kwargs)

    def test_rejects_valid_until_not_after_valid_from(self) -> None:
        kwargs = self._valid_kwargs()
        kwargs["valid_until"] = kwargs["valid_from"]
        with pytest.raises(InvariantViolation):
            AuthorizationGrant(**kwargs)

    def test_rejects_empty_created_by(self) -> None:
        kwargs = self._valid_kwargs()
        kwargs["created_by"] = ""
        with pytest.raises(InvariantViolation):
            AuthorizationGrant(**kwargs)

    def test_rejects_naive_revoked_at(self) -> None:
        kwargs = self._valid_kwargs()
        kwargs["revoked_at"] = datetime(2026, 1, 15)  # naive
        with pytest.raises(InvariantViolation):
            AuthorizationGrant(**kwargs)


class TestAuthorizationGrantIsActive:
    def _grant(self, *, revoked_at: datetime | None = None) -> AuthorizationGrant:
        return AuthorizationGrant(
            id=_grant_id(),
            authorized_by="ciso@example.com",
            authorizing_organization="Example Corp",
            target_specification=spec(TargetSpecificationType.IP_ADDRESS, "203.0.113.5"),
            valid_from=utc(2026, 1, 1),
            valid_until=utc(2026, 2, 1),
            created_by="admin@kingusecurity.com",
            revoked_at=revoked_at,
        )

    def test_active_within_window(self) -> None:
        assert self._grant().is_active(utc(2026, 1, 15)) is True

    def test_active_at_valid_from_boundary(self) -> None:
        assert self._grant().is_active(utc(2026, 1, 1)) is True

    def test_active_at_valid_until_boundary(self) -> None:
        assert self._grant().is_active(utc(2026, 2, 1)) is True

    def test_inactive_before_valid_from(self) -> None:
        assert self._grant().is_active(utc(2025, 12, 31)) is False

    def test_inactive_after_valid_until(self) -> None:
        assert self._grant().is_active(utc(2026, 2, 2)) is False

    def test_inactive_after_revocation_even_within_window(self) -> None:
        grant = self._grant(revoked_at=utc(2026, 1, 10))
        assert grant.is_active(utc(2026, 1, 15)) is False

    def test_active_before_revocation_within_window(self) -> None:
        grant = self._grant(revoked_at=utc(2026, 1, 10))
        assert grant.is_active(utc(2026, 1, 5)) is True


# ---------------------------------------------------------------------------
# covers_target(): IP_ADDRESS spec
# ---------------------------------------------------------------------------


class TestCoversTargetIpAddress:
    def test_matching_ip_is_covered(self) -> None:
        result = covers_target(
            spec(TargetSpecificationType.IP_ADDRESS, "203.0.113.5"),
            target("203.0.113.5", TargetType.IP_ADDRESS),
        )
        assert result.covered

    def test_normalizes_equivalent_ipv6_forms(self) -> None:
        result = covers_target(
            spec(TargetSpecificationType.IP_ADDRESS, "::1"),
            target("0:0:0:0:0:0:0:1", TargetType.IP_ADDRESS),
        )
        assert result.covered

    def test_mismatched_ip_is_not_covered(self) -> None:
        result = covers_target(
            spec(TargetSpecificationType.IP_ADDRESS, "203.0.113.5"),
            target("203.0.113.6", TargetType.IP_ADDRESS),
        )
        assert not result.covered
        assert result.outcome == ScopeCheckOutcome.HOST_MISMATCH

    def test_non_ip_target_type_mismatch(self) -> None:
        result = covers_target(
            spec(TargetSpecificationType.IP_ADDRESS, "203.0.113.5"),
            target("example.com", TargetType.HOSTNAME),
        )
        assert result.outcome == ScopeCheckOutcome.TYPE_MISMATCH


# ---------------------------------------------------------------------------
# covers_target(): NETWORK spec
# ---------------------------------------------------------------------------


class TestCoversTargetNetwork:
    def test_ip_inside_network_is_covered(self) -> None:
        result = covers_target(
            spec(TargetSpecificationType.NETWORK, "203.0.113.0/24"),
            target("203.0.113.42", TargetType.IP_ADDRESS),
        )
        assert result.covered

    def test_ip_outside_network_is_not_covered(self) -> None:
        result = covers_target(
            spec(TargetSpecificationType.NETWORK, "203.0.113.0/24"),
            target("198.51.100.1", TargetType.IP_ADDRESS),
        )
        assert result.outcome == ScopeCheckOutcome.ADDRESS_NOT_IN_NETWORK

    def test_ip_version_mismatch_against_network(self) -> None:
        result = covers_target(
            spec(TargetSpecificationType.NETWORK, "203.0.113.0/24"),
            target("::1", TargetType.IP_ADDRESS),
        )
        assert result.outcome == ScopeCheckOutcome.IP_VERSION_MISMATCH

    def test_narrower_network_target_is_covered(self) -> None:
        result = covers_target(
            spec(TargetSpecificationType.NETWORK, "10.0.0.0/16"),
            target("10.0.5.0/24", TargetType.NETWORK),
        )
        assert result.covered

    def test_wider_network_target_is_not_covered(self) -> None:
        result = covers_target(
            spec(TargetSpecificationType.NETWORK, "10.0.5.0/24"),
            target("10.0.0.0/16", TargetType.NETWORK),
        )
        assert result.outcome == ScopeCheckOutcome.NETWORK_NOT_SUBNET

    def test_disjoint_network_target_is_not_covered(self) -> None:
        result = covers_target(
            spec(TargetSpecificationType.NETWORK, "10.0.0.0/24"),
            target("10.1.0.0/24", TargetType.NETWORK),
        )
        assert result.outcome == ScopeCheckOutcome.NETWORK_NOT_SUBNET

    def test_mixed_ipv4_ipv6_network_vs_network_is_refused(self) -> None:
        result = covers_target(
            spec(TargetSpecificationType.NETWORK, "10.0.0.0/24"),
            target("2001:db8::/32", TargetType.NETWORK),
        )
        assert result.outcome == ScopeCheckOutcome.IP_VERSION_MISMATCH

    def test_non_ip_target_type_mismatch(self) -> None:
        result = covers_target(
            spec(TargetSpecificationType.NETWORK, "10.0.0.0/24"),
            target("example.com", TargetType.HOSTNAME),
        )
        assert result.outcome == ScopeCheckOutcome.TYPE_MISMATCH


# ---------------------------------------------------------------------------
# covers_target(): HOSTNAME spec
# ---------------------------------------------------------------------------


class TestCoversTargetHostname:
    def test_exact_match_is_covered(self) -> None:
        result = covers_target(
            spec(TargetSpecificationType.HOSTNAME, "api.example.com"),
            target("api.example.com", TargetType.HOSTNAME),
        )
        assert result.covered

    def test_case_insensitive_match_is_covered(self) -> None:
        result = covers_target(
            spec(TargetSpecificationType.HOSTNAME, "API.example.com"),
            target("api.EXAMPLE.com", TargetType.HOSTNAME),
        )
        assert result.covered

    def test_mismatched_hostname_is_not_covered(self) -> None:
        result = covers_target(
            spec(TargetSpecificationType.HOSTNAME, "api.example.com"),
            target("other.example.com", TargetType.HOSTNAME),
        )
        assert result.outcome == ScopeCheckOutcome.HOST_MISMATCH

    def test_matches_url_target_with_same_host(self) -> None:
        result = covers_target(
            spec(TargetSpecificationType.HOSTNAME, "api.example.com"),
            target("https://api.example.com/v1", TargetType.URL),
        )
        assert result.covered

    def test_non_hostname_capable_target_type_mismatch(self) -> None:
        result = covers_target(
            spec(TargetSpecificationType.HOSTNAME, "api.example.com"),
            target("203.0.113.5", TargetType.IP_ADDRESS),
        )
        assert result.outcome == ScopeCheckOutcome.TYPE_MISMATCH


# ---------------------------------------------------------------------------
# covers_target(): WILDCARD_HOSTNAME spec
# ---------------------------------------------------------------------------


class TestCoversTargetWildcardHostname:
    def test_direct_subdomain_is_covered(self) -> None:
        result = covers_target(
            spec(TargetSpecificationType.WILDCARD_HOSTNAME, "*.example.com"),
            target("api.example.com", TargetType.HOSTNAME),
        )
        assert result.covered

    def test_multi_level_subdomain_is_covered(self) -> None:
        result = covers_target(
            spec(TargetSpecificationType.WILDCARD_HOSTNAME, "*.example.com"),
            target("a.b.example.com", TargetType.HOSTNAME),
        )
        assert result.covered

    def test_bare_domain_itself_is_not_covered(self) -> None:
        result = covers_target(
            spec(TargetSpecificationType.WILDCARD_HOSTNAME, "*.example.com"),
            target("example.com", TargetType.HOSTNAME),
        )
        assert result.outcome == ScopeCheckOutcome.HOST_MISMATCH

    def test_unrelated_domain_is_not_covered(self) -> None:
        result = covers_target(
            spec(TargetSpecificationType.WILDCARD_HOSTNAME, "*.example.com"),
            target("api.other.com", TargetType.HOSTNAME),
        )
        assert result.outcome == ScopeCheckOutcome.HOST_MISMATCH

    def test_matches_url_target_subdomain(self) -> None:
        result = covers_target(
            spec(TargetSpecificationType.WILDCARD_HOSTNAME, "*.example.com"),
            target("https://api.example.com/v1", TargetType.URL),
        )
        assert result.covered


# ---------------------------------------------------------------------------
# covers_target(): URL_PREFIX spec
# ---------------------------------------------------------------------------


class TestCoversTargetUrlPrefix:
    def test_root_path_grant_covers_any_path(self) -> None:
        result = covers_target(
            spec(TargetSpecificationType.URL_PREFIX, "https://example.com/"),
            target("https://example.com/admin/panel", TargetType.URL),
        )
        assert result.covered

    def test_path_scoped_grant_covers_same_path(self) -> None:
        result = covers_target(
            spec(TargetSpecificationType.URL_PREFIX, "https://example.com/app/"),
            target("https://example.com/app/", TargetType.URL),
        )
        assert result.covered

    def test_path_scoped_grant_covers_child_path(self) -> None:
        result = covers_target(
            spec(TargetSpecificationType.URL_PREFIX, "https://example.com/app/"),
            target("https://example.com/app/settings", TargetType.URL),
        )
        assert result.covered

    def test_path_scoped_grant_does_not_cover_sibling_path(self) -> None:
        result = covers_target(
            spec(TargetSpecificationType.URL_PREFIX, "https://example.com/app/"),
            target("https://example.com/other/", TargetType.URL),
        )
        assert result.outcome == ScopeCheckOutcome.PATH_NOT_COVERED

    def test_scheme_mismatch_is_not_covered(self) -> None:
        result = covers_target(
            spec(TargetSpecificationType.URL_PREFIX, "https://example.com/"),
            target("http://example.com/", TargetType.URL),
        )
        assert result.outcome == ScopeCheckOutcome.SCHEME_MISMATCH

    def test_host_mismatch_is_not_covered(self) -> None:
        result = covers_target(
            spec(TargetSpecificationType.URL_PREFIX, "https://example.com/"),
            target("https://other.com/", TargetType.URL),
        )
        assert result.outcome == ScopeCheckOutcome.HOST_MISMATCH

    def test_explicit_port_mismatch_is_not_covered(self) -> None:
        result = covers_target(
            spec(TargetSpecificationType.URL_PREFIX, "https://example.com/"),
            target("https://example.com:8443/", TargetType.URL),
        )
        assert result.outcome == ScopeCheckOutcome.PORT_MISMATCH

    def test_default_port_matches_explicit_default_port(self) -> None:
        result = covers_target(
            spec(TargetSpecificationType.URL_PREFIX, "https://example.com/"),
            target("https://example.com:443/", TargetType.URL),
        )
        assert result.covered

    def test_non_url_target_type_mismatch(self) -> None:
        result = covers_target(
            spec(TargetSpecificationType.URL_PREFIX, "https://example.com/"),
            target("example.com", TargetType.HOSTNAME),
        )
        assert result.outcome == ScopeCheckOutcome.TYPE_MISMATCH


# ---------------------------------------------------------------------------
# satisfies_tier(): validation
# ---------------------------------------------------------------------------


class TestSatisfiesTierValidation:
    def test_rejects_invalid_required_tier(self) -> None:
        with pytest.raises(InvariantViolation):
            satisfies_tier(
                spec(TargetSpecificationType.IP_ADDRESS, "203.0.113.5"),
                target("203.0.113.5", TargetType.IP_ADDRESS),
                "host_any_port",  # type: ignore[arg-type]
            )


# ---------------------------------------------------------------------------
# satisfies_tier(): HOST_PORT_PATH delegates to covers_target()
# ---------------------------------------------------------------------------


class TestSatisfiesTierHostPortPath:
    def test_matches_covers_target_for_sibling_path(self) -> None:
        result = satisfies_tier(
            spec(TargetSpecificationType.URL_PREFIX, "https://example.com/app/"),
            target("https://example.com/other/", TargetType.URL),
            ScannerSurfaceTier.HOST_PORT_PATH,
        )
        assert result.outcome == ScopeCheckOutcome.PATH_NOT_COVERED

    def test_matches_covers_target_for_child_path(self) -> None:
        result = satisfies_tier(
            spec(TargetSpecificationType.URL_PREFIX, "https://example.com/app/"),
            target("https://example.com/app/settings", TargetType.URL),
            ScannerSurfaceTier.HOST_PORT_PATH,
        )
        assert result.covered


# ---------------------------------------------------------------------------
# satisfies_tier(): HOST_ANY_PORT (nmap) - Blocking 1
# ---------------------------------------------------------------------------


class TestSatisfiesTierHostAnyPort:
    def test_url_prefix_grant_is_refused_even_at_root_path(self) -> None:
        result = satisfies_tier(
            spec(TargetSpecificationType.URL_PREFIX, "https://example.com/"),
            target("https://example.com/", TargetType.URL),
            ScannerSurfaceTier.HOST_ANY_PORT,
        )
        assert not result.covered
        assert result.outcome == ScopeCheckOutcome.TYPE_MISMATCH

    def test_ip_address_grant_is_sufficient(self) -> None:
        result = satisfies_tier(
            spec(TargetSpecificationType.IP_ADDRESS, "203.0.113.5"),
            target("203.0.113.5", TargetType.IP_ADDRESS),
            ScannerSurfaceTier.HOST_ANY_PORT,
        )
        assert result.covered

    def test_network_grant_is_sufficient(self) -> None:
        result = satisfies_tier(
            spec(TargetSpecificationType.NETWORK, "203.0.113.0/24"),
            target("203.0.113.5", TargetType.IP_ADDRESS),
            ScannerSurfaceTier.HOST_ANY_PORT,
        )
        assert result.covered

    def test_hostname_grant_is_sufficient(self) -> None:
        result = satisfies_tier(
            spec(TargetSpecificationType.HOSTNAME, "api.example.com"),
            target("api.example.com", TargetType.HOSTNAME),
            ScannerSurfaceTier.HOST_ANY_PORT,
        )
        assert result.covered


# ---------------------------------------------------------------------------
# satisfies_tier(): HOST_PORT_ANY_PATH - "accidental sufficiency"
# ---------------------------------------------------------------------------


class TestSatisfiesTierHostPortAnyPath:
    def test_path_scoped_url_grant_accidentally_covers_sibling_path(self) -> None:
        """A path-scoped grant satisfies a path-ignorant scanner "by
        accident" - the scanner ignores the target's path regardless of
        what the grant scoped it to."""
        result = satisfies_tier(
            spec(TargetSpecificationType.URL_PREFIX, "https://example.com/app/"),
            target("https://example.com/other/admin", TargetType.URL),
            ScannerSurfaceTier.HOST_PORT_ANY_PATH,
        )
        assert result.covered

    def test_host_mismatch_still_refused_regardless_of_tier(self) -> None:
        result = satisfies_tier(
            spec(TargetSpecificationType.URL_PREFIX, "https://example.com/app/"),
            target("https://other.com/app/", TargetType.URL),
            ScannerSurfaceTier.HOST_PORT_ANY_PATH,
        )
        assert result.outcome == ScopeCheckOutcome.HOST_MISMATCH

    def test_port_mismatch_still_refused_regardless_of_tier(self) -> None:
        result = satisfies_tier(
            spec(TargetSpecificationType.URL_PREFIX, "https://example.com/app/"),
            target("https://example.com:8443/app/", TargetType.URL),
            ScannerSurfaceTier.HOST_PORT_ANY_PATH,
        )
        assert result.outcome == ScopeCheckOutcome.PORT_MISMATCH

    def test_non_url_spec_delegates_to_covers_target(self) -> None:
        result = satisfies_tier(
            spec(TargetSpecificationType.NETWORK, "203.0.113.0/24"),
            target("203.0.113.5", TargetType.IP_ADDRESS),
            ScannerSurfaceTier.HOST_PORT_ANY_PATH,
        )
        assert result.covered
