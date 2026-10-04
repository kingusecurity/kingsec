"""The AuthorizationGrant aggregate: scope enforcement for assessments.

Phase 4 (authorization scope enforcement). Before this module, KingSec's only
authorization concept was ``Authorization`` (authorization.py) - a free-text
``scope: str`` attached to a single assessment after the fact, read only for
report-cover display. Nothing checked a requested target against it before an
assessment could run.

``AuthorizationGrant`` is a separate, first-class aggregate rather than a
field on ``Assessment``: a grant is checkable before any assessment exists,
and a single grant can cover many assessments across an engagement. It carries
its own validity window (``valid_from``/``valid_until``) independent of any
assessment's own lifecycle.

Two distinct matching functions, both pure (no I/O, no DNS resolution -
resolving a hostname to see if it "happens to" land in a granted network
would let an attacker-controlled DNS answer decide authorization, so this
module only ever compares the text both sides were given):

    covers_target()  - STRICT: does the grant's specification cover a
                        target's own declared value, respecting whatever
                        precision (host, port, path) both sides carry?

    satisfies_tier()  - TIER-AWARE: does the grant license a scanner whose
                        real invocation reaches further than the target
                        alone suggests? A URL Target with a path tells you
                        nothing about whether nmap's underlying invocation
                        sweeps the whole host regardless of that path (see
                        ScannerSurfaceTier in scanner.py) - satisfies_tier()
                        is what effective_scan_surface() checks against,
                        never covers_target() alone.
"""

from __future__ import annotations

import ipaddress
import urllib.parse
from dataclasses import dataclass
from datetime import datetime
from enum import Enum

from ._validation import ensure_non_empty, ensure_timezone_aware
from .errors import InvariantViolation
from .identifiers import AuthorizationGrantId
from .scanner import ScannerSurfaceTier
from .target import Target, TargetType, decompose_url

# ---------------------------------------------------------------------------
# TargetSpecification
# ---------------------------------------------------------------------------


class TargetSpecificationType(Enum):
    """The shape of scope an AuthorizationGrant's specification expresses."""

    IP_ADDRESS = "ip_address"
    NETWORK = "network"
    HOSTNAME = "hostname"
    WILDCARD_HOSTNAME = "wildcard_hostname"
    URL_PREFIX = "url_prefix"


def _validate_hostname_text(value: str) -> None:
    """Validate *value* as a hostname, reusing Target's own rules.

    Never re-implements Target._validate_format()'s hostname regex - builds
    a throwaway Target(value, TargetType.HOSTNAME) purely for the
    InvariantViolation it raises on malformed input.
    """
    Target(value, TargetType.HOSTNAME)


@dataclass(frozen=True, slots=True)
class TargetSpecification:
    """What an AuthorizationGrant covers: one of five shapes.

    ``value``'s expected format is driven entirely by ``type``:
        IP_ADDRESS         a single IP literal ("203.0.113.5")
        NETWORK             a CIDR range ("203.0.113.0/24")
        HOSTNAME            an exact hostname ("api.example.com")
        WILDCARD_HOSTNAME   "*." plus a hostname ("*.example.com") - covers
                            any strict subdomain, never the bare domain
                            itself
        URL_PREFIX          a URL whose path is a prefix ("https://
                            example.com/app/" covers that path and
                            everything beneath it; a path of "/" covers the
                            whole host:port)
    """

    type: TargetSpecificationType
    value: str

    def __post_init__(self) -> None:
        if not isinstance(self.type, TargetSpecificationType):
            raise InvariantViolation(f"TargetSpecification type must be a TargetSpecificationType: {self.type!r}")
        ensure_non_empty(self.value, "TargetSpecification value")
        self._validate_format()

    def _validate_format(self) -> None:
        tp = self.type
        if tp == TargetSpecificationType.IP_ADDRESS:
            Target(self.value, TargetType.IP_ADDRESS)
        elif tp == TargetSpecificationType.NETWORK:
            Target(self.value, TargetType.NETWORK)
        elif tp == TargetSpecificationType.HOSTNAME:
            _validate_hostname_text(self.value)
        elif tp == TargetSpecificationType.WILDCARD_HOSTNAME:
            if not self.value.startswith("*."):
                raise InvariantViolation(f"WILDCARD_HOSTNAME must start with '*.': {self.value!r}")
            _validate_hostname_text(self.value[2:])
        elif tp == TargetSpecificationType.URL_PREFIX:
            Target(self.value, TargetType.URL)


# ---------------------------------------------------------------------------
# AuthorizationGrant
# ---------------------------------------------------------------------------


@dataclass(frozen=True, slots=True)
class AuthorizationGrant:
    """Evidence that a target (or range of targets) is authorized to scan.

    Independent of any single Assessment: checkable before one exists, and
    one grant can cover many assessments across an engagement.
    """

    id: AuthorizationGrantId
    authorized_by: str
    authorizing_organization: str
    target_specification: TargetSpecification
    valid_from: datetime
    valid_until: datetime
    created_by: str
    revoked_at: datetime | None = None

    def __post_init__(self) -> None:
        if not isinstance(self.id, AuthorizationGrantId):
            raise InvariantViolation(f"AuthorizationGrant id must be an AuthorizationGrantId: {self.id!r}")
        ensure_non_empty(self.authorized_by, "authorized_by")
        ensure_non_empty(self.authorizing_organization, "authorizing_organization")
        if not isinstance(self.target_specification, TargetSpecification):
            raise InvariantViolation("AuthorizationGrant target_specification must be a TargetSpecification")
        ensure_timezone_aware(self.valid_from, "valid_from")
        ensure_timezone_aware(self.valid_until, "valid_until")
        if self.valid_until <= self.valid_from:
            raise InvariantViolation("AuthorizationGrant valid_until must be after valid_from")
        ensure_non_empty(self.created_by, "created_by")
        if self.revoked_at is not None:
            ensure_timezone_aware(self.revoked_at, "revoked_at")

    def is_active(self, at: datetime) -> bool:
        """Whether this grant is live at *at*: within its window and not revoked."""
        ensure_timezone_aware(at, "at")
        if self.revoked_at is not None and at >= self.revoked_at:
            return False
        return self.valid_from <= at <= self.valid_until


# ---------------------------------------------------------------------------
# Scope-check result
# ---------------------------------------------------------------------------


class ScopeCheckOutcome(Enum):
    """Why a target was, or was not, covered by a grant's specification.

    Named outcomes rather than a bare bool so a refused scan's audit trail
    can name the deciding rule instead of just "not authorized".
    """

    COVERED = "covered"
    TYPE_MISMATCH = "type_mismatch"
    SCHEME_MISMATCH = "scheme_mismatch"
    HOST_MISMATCH = "host_mismatch"
    PORT_MISMATCH = "port_mismatch"
    PATH_NOT_COVERED = "path_not_covered"
    NETWORK_NOT_SUBNET = "network_not_subnet"
    IP_VERSION_MISMATCH = "ip_version_mismatch"
    ADDRESS_NOT_IN_NETWORK = "address_not_in_network"


@dataclass(frozen=True, slots=True)
class ScopeCheckResult:
    """The outcome of a single covers_target()/satisfies_tier() check."""

    outcome: ScopeCheckOutcome
    detail: str = ""

    @property
    def covered(self) -> bool:
        return self.outcome == ScopeCheckOutcome.COVERED


# ---------------------------------------------------------------------------
# Strict matching: covers_target()
# ---------------------------------------------------------------------------


def covers_target(spec: TargetSpecification, target: Target) -> ScopeCheckResult:
    """Does *spec* cover *target*'s own declared value?

    Strict: respects whatever precision (host, port, path) the target
    itself carries. Never resolves DNS - a HOSTNAME/WILDCARD_HOSTNAME spec
    is compared against a target's own textual host, never against where
    that host currently resolves.
    """
    if spec.type == TargetSpecificationType.IP_ADDRESS:
        return _ip_spec_covers(spec, target)
    if spec.type == TargetSpecificationType.NETWORK:
        return _network_spec_covers(spec, target)
    if spec.type == TargetSpecificationType.HOSTNAME:
        return _hostname_spec_covers(spec, target, wildcard=False)
    if spec.type == TargetSpecificationType.WILDCARD_HOSTNAME:
        return _hostname_spec_covers(spec, target, wildcard=True)
    if spec.type == TargetSpecificationType.URL_PREFIX:
        return _url_spec_covers(spec, target)
    raise InvariantViolation(f"Unhandled TargetSpecificationType: {spec.type!r}")


def _normalize_ip(value: str) -> str:
    return str(ipaddress.ip_address(value))


def _ip_spec_covers(spec: TargetSpecification, target: Target) -> ScopeCheckResult:
    if target.type != TargetType.IP_ADDRESS:
        return ScopeCheckResult(
            ScopeCheckOutcome.TYPE_MISMATCH,
            f"grant covers a single IP address, target is {target.type.value}",
        )
    if _normalize_ip(spec.value) == _normalize_ip(target.value):
        return ScopeCheckResult(ScopeCheckOutcome.COVERED)
    return ScopeCheckResult(
        ScopeCheckOutcome.HOST_MISMATCH,
        f"{target.value} does not match granted address {spec.value}",
    )


def _network_spec_covers(spec: TargetSpecification, target: Target) -> ScopeCheckResult:
    grant_network = ipaddress.ip_network(spec.value, strict=False)
    if target.type == TargetType.IP_ADDRESS:
        address = ipaddress.ip_address(target.value)
        if address.version != grant_network.version:
            return ScopeCheckResult(
                ScopeCheckOutcome.IP_VERSION_MISMATCH,
                f"{target.value} is IPv{address.version}, grant network {spec.value} is IPv{grant_network.version}",
            )
        if address in grant_network:
            return ScopeCheckResult(ScopeCheckOutcome.COVERED)
        return ScopeCheckResult(
            ScopeCheckOutcome.ADDRESS_NOT_IN_NETWORK,
            f"{target.value} is not in {spec.value}",
        )
    if target.type == TargetType.NETWORK:
        target_network = ipaddress.ip_network(target.value, strict=False)
        try:
            # mypy's ipaddress stub overloads subnet_of() per concrete
            # version (IPv4Network.subnet_of(IPv4Network) / IPv6-only) and
            # cannot narrow the union ip_network() returns - the version
            # mismatch this would catch statically is instead caught at
            # runtime by the except clause immediately below.
            is_subnet = target_network.subnet_of(grant_network)  # type: ignore[arg-type]
        except TypeError:
            # ipaddress.subnet_of() raises TypeError for mixed IPv4/IPv6
            # comparisons rather than returning False - refuse rather than
            # let that exception surface as an unhandled error.
            return ScopeCheckResult(
                ScopeCheckOutcome.IP_VERSION_MISMATCH,
                f"{target.value} and grant network {spec.value} are different IP versions",
            )
        if is_subnet:
            return ScopeCheckResult(ScopeCheckOutcome.COVERED)
        return ScopeCheckResult(
            ScopeCheckOutcome.NETWORK_NOT_SUBNET,
            f"{target.value} is not a subnet of {spec.value}",
        )
    return ScopeCheckResult(
        ScopeCheckOutcome.TYPE_MISMATCH,
        f"grant covers a network, target is {target.type.value}",
    )


def _target_host_text(target: Target) -> str | None:
    """The comparable host string for *target*, or None if it has none.

    Deliberately excludes IP_ADDRESS: a HOSTNAME/WILDCARD_HOSTNAME spec is
    written in hostname terms, so an IP-address target is a type mismatch,
    not a coincidental string comparison against the IP's own text.

    Never resolves DNS: a URL target's host comes from decompose_url()'s
    own parsing of the target's literal value, not from a lookup.
    """
    if target.type == TargetType.HOSTNAME:
        return target.value
    if target.type == TargetType.URL:
        return decompose_url(target).host
    return None


def _hostname_spec_covers(spec: TargetSpecification, target: Target, *, wildcard: bool) -> ScopeCheckResult:
    candidate = _target_host_text(target)
    if candidate is None:
        return ScopeCheckResult(
            ScopeCheckOutcome.TYPE_MISMATCH,
            f"grant covers a hostname, target is {target.type.value}",
        )
    if not wildcard:
        if candidate.lower() == spec.value.lower():
            return ScopeCheckResult(ScopeCheckOutcome.COVERED)
        return ScopeCheckResult(
            ScopeCheckOutcome.HOST_MISMATCH,
            f"{candidate} does not match granted hostname {spec.value}",
        )
    pattern = spec.value[2:]  # strip the leading "*."
    pattern_labels = pattern.lower().split(".")
    candidate_labels = candidate.lower().split(".")
    if len(candidate_labels) > len(pattern_labels) and candidate_labels[-len(pattern_labels) :] == pattern_labels:
        return ScopeCheckResult(ScopeCheckOutcome.COVERED)
    return ScopeCheckResult(
        ScopeCheckOutcome.HOST_MISMATCH,
        f"{candidate} is not a subdomain of {pattern}",
    )


def _url_spec_covers(spec: TargetSpecification, target: Target) -> ScopeCheckResult:
    if target.type != TargetType.URL:
        return ScopeCheckResult(
            ScopeCheckOutcome.TYPE_MISMATCH,
            f"grant covers a URL prefix, target is {target.type.value}",
        )
    grant_components = decompose_url(Target(spec.value, TargetType.URL))
    target_components = decompose_url(target)
    if grant_components.scheme != target_components.scheme:
        return ScopeCheckResult(
            ScopeCheckOutcome.SCHEME_MISMATCH,
            f"{target_components.scheme} does not match granted scheme {grant_components.scheme}",
        )
    if grant_components.host.lower() != target_components.host.lower():
        return ScopeCheckResult(
            ScopeCheckOutcome.HOST_MISMATCH,
            f"{target_components.host} does not match granted host {grant_components.host}",
        )
    if grant_components.port != target_components.port:
        return ScopeCheckResult(
            ScopeCheckOutcome.PORT_MISMATCH,
            f"{target_components.port} does not match granted port {grant_components.port}",
        )
    grant_path = grant_components.path or "/"
    target_path = target_components.path or "/"
    if grant_path == "/":
        return ScopeCheckResult(ScopeCheckOutcome.COVERED)
    prefix = grant_path.rstrip("/") + "/"
    if target_path == grant_path.rstrip("/") or target_path.startswith(prefix):
        return ScopeCheckResult(ScopeCheckOutcome.COVERED)
    return ScopeCheckResult(
        ScopeCheckOutcome.PATH_NOT_COVERED,
        f"{target_path} is not under granted path {grant_path}",
    )


# ---------------------------------------------------------------------------
# Tier-aware matching: satisfies_tier()
# ---------------------------------------------------------------------------


def _url_with_root_path(value: str) -> str:
    """Reconstruct *value* (an already-validated URL string) with its path
    collapsed to "/", keeping only scheme and host:port authority."""
    parsed = urllib.parse.urlparse(value)
    return f"{parsed.scheme}://{parsed.netloc}/"


def satisfies_tier(
    spec: TargetSpecification,
    target: Target,
    required_tier: ScannerSurfaceTier,
) -> ScopeCheckResult:
    """Does *spec* license a scanner whose real invocation reaches
    *required_tier*'s extent of surface against *target*?

    Blocking 1: a grant's coverage of the target's own declared value is
    not the same question as whether it covers what a scanner actually
    touches once it runs (see ScannerSurfaceTier in scanner.py). This is
    the check effective_scan_surface() uses, never covers_target() alone.
    """
    if not isinstance(required_tier, ScannerSurfaceTier):
        raise InvariantViolation(f"required_tier must be a ScannerSurfaceTier: {required_tier!r}")

    if required_tier == ScannerSurfaceTier.HOST_PORT_PATH:
        # The scanner respects the target's own path, so ordinary strict
        # coverage is exactly the right question.
        return covers_target(spec, target)

    if required_tier == ScannerSurfaceTier.HOST_ANY_PORT:
        if spec.type == TargetSpecificationType.URL_PREFIX:
            return ScopeCheckResult(
                ScopeCheckOutcome.TYPE_MISMATCH,
                "a URL-scoped grant does not license a host-wide, any-port scan - a separate host-level grant is required",
            )
        # IP_ADDRESS/NETWORK/HOSTNAME/WILDCARD_HOSTNAME specs never carry a
        # port or path, so covers_target()'s check for these types is
        # already host-only and needs no separate host-only variant.
        return covers_target(spec, target)

    # ScannerSurfaceTier.HOST_PORT_ANY_PATH: the scanner ignores whatever
    # path the target specifies, so a grant narrowed only by path (not by
    # host or port) is broad enough in practice - "accidental sufficiency"
    # from the scanner's own behaviour, not from the grant's own rule.
    if spec.type != TargetSpecificationType.URL_PREFIX:
        return covers_target(spec, target)
    root_spec = TargetSpecification(type=TargetSpecificationType.URL_PREFIX, value=_url_with_root_path(spec.value))
    return _url_spec_covers(root_spec, target)
