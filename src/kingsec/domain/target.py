"""The Target value object: what an assessment is assessing.

A frozen value object. The domain validates the format of the target value
against its declared type so that malformed input is caught before it reaches
the scanner infrastructure.  Only the standard library is used here so that
the domain layer remains pure.
"""

from __future__ import annotations

import ipaddress
import re
import urllib.parse
from dataclasses import dataclass
from enum import Enum

from ._validation import ensure_non_empty
from .errors import InvariantViolation, TargetDecompositionError


class TargetType(Enum):
    """The kind of thing being assessed. Drives how adapters interpret it."""

    HOSTNAME = "hostname"
    IP_ADDRESS = "ip_address"
    URL = "url"
    NETWORK = "network"  # e.g. a CIDR range


# RFC 1034 / RFC 1123 hostname label: alphanumeric + hyphen, no leading/trailing hyphen.
_HOSTNAME_LABEL = re.compile(r"^[a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?$")


def _validate_hostname(value: str) -> None:
    """Validate a DNS hostname (RFC 1034, RFC 1123)."""
    if len(value) > 253:
        raise InvariantViolation(f"hostname too long ({len(value)} chars, max 253)")
    for label in value.rstrip(".").split("."):
        if not label:
            raise InvariantViolation("hostname contains an empty label")
        if not _HOSTNAME_LABEL.match(label):
            raise InvariantViolation(f"invalid hostname label: {label!r}")


@dataclass(frozen=True, slots=True)
class Target:
    """An immutable description of the assessment's subject."""

    value: str
    type: TargetType

    def __post_init__(self) -> None:
        ensure_non_empty(self.value, "Target value")
        if not isinstance(self.type, TargetType):
            raise InvariantViolation(f"Invalid target type: {self.type}")
        self._validate_format()

    def _validate_format(self) -> None:
        """Validate *value* matches the format required by *type*."""
        tp = self.type
        if tp == TargetType.IP_ADDRESS:
            try:
                ipaddress.ip_address(self.value)
            except ValueError as exc:
                raise InvariantViolation(str(exc)) from exc
        elif tp == TargetType.NETWORK:
            try:
                ipaddress.ip_network(self.value, strict=False)
            except ValueError as exc:
                raise InvariantViolation(str(exc)) from exc
        elif tp == TargetType.HOSTNAME:
            _validate_hostname(self.value)
        elif tp == TargetType.URL:
            parsed = urllib.parse.urlparse(self.value)
            if parsed.scheme not in ("http", "https"):
                raise InvariantViolation(f"URL scheme must be http or https, got {parsed.scheme!r}")
            if not parsed.netloc:
                raise InvariantViolation("URL must have a network location")
            if parsed.username is not None or parsed.password is not None:
                raise InvariantViolation(
                    "URL must not contain embedded credentials - reject rather than silently use or discard them"
                )
            try:
                raw_port = parsed.port
            except ValueError as exc:
                # Also catches an unbracketed IPv6 authority ("http://::1/") -
                # urllib.parse treats the extra colons as an ambiguous port
                # separator and raises here rather than guessing a host.
                raise InvariantViolation(f"URL port is not numeric: {exc}") from exc
            if raw_port is not None and not (1 <= raw_port <= 65535):
                raise InvariantViolation(f"URL port {raw_port} is out of range (1-65535)")
            if not parsed.hostname:
                raise InvariantViolation("URL has no usable host")

    def __str__(self) -> str:
        return f"{self.value} ({self.type.value})"


_DEFAULT_PORT_BY_SCHEME = {"http": 80, "https": 443}


def is_ipv6_literal(value: str) -> bool:
    """Return True if *value* parses as a literal IPv6 address (not IPv4).

    Pure, reusable by both decompose_url() (Section 7's URL case) and any
    adapter branching on a non-URL target's own value (Phase 2B Task 2
    Addition 1 - an IP_ADDRESS/NETWORK target holding an IPv6 literal needs
    the same -6 handling a URL-derived one does; this is the one place both
    paths ask the same question).
    """
    try:
        return ipaddress.ip_address(value).version == 6
    except ValueError:
        return False


@dataclass(frozen=True, slots=True)
class UrlComponents:
    """The scan-usable pieces of a URL target, decomposed once.

    Computed on demand from an already-validated Target.value - never
    persisted (Phase 2B Task 2 Section 4/9: this is what keeps this feature
    migration-free). port is always resolved to a concrete number, explicit
    or the scheme's default, so a consumer never has to special-case "no
    port given."
    """

    scheme: str
    host: str
    is_ipv6: bool
    port: int
    port_is_explicit: bool
    path: str


def decompose_url(target: Target) -> UrlComponents:
    """Break a URL Target into host/port/scheme components for scanning.

    Decision 3 (applied): the credential/port-range/unbracketed-IPv6 checks
    below now duplicate validation Target._validate_format() already
    enforces at construction time - every Target reachable in this
    codebase goes through the normal dataclass constructor (confirmed: no
    call site builds one via object.__new__ or otherwise bypasses
    __post_init__), so for any Target actually holding TargetType.URL,
    these branches can no longer raise in practice. Kept anyway, as cheap
    defense-in-depth against a future bypass rather than deleted, and
    because deleting them would silently make this function trust a
    precondition it cannot itself verify. The one check that is NOT
    redundant is the very next one: calling this function on a Target
    whose type isn't URL at all is a caller-contract violation, not a
    data-validation gap, and Target._validate_format() has no way to
    prevent that misuse - only decompose_url() itself can.
    """
    if target.type is not TargetType.URL:
        raise TargetDecompositionError(f"decompose_url() requires a URL target, got {target.type.value!r}")

    parsed = urllib.parse.urlparse(target.value)

    if parsed.username is not None or parsed.password is not None:
        raise TargetDecompositionError(
            "URL must not contain embedded credentials - reject rather than silently use or discard them"
        )

    try:
        raw_port = parsed.port
    except ValueError as exc:
        raise TargetDecompositionError(f"URL port is not numeric: {exc}") from exc

    if raw_port is not None and not (1 <= raw_port <= 65535):
        raise TargetDecompositionError(f"URL port {raw_port} is out of range (1-65535)")

    host = parsed.hostname
    if not host:
        raise TargetDecompositionError("URL has no usable host")

    # A bracketed IPv6 literal ("[::1]") is stripped to "::1" by .hostname
    # already; an unbracketed IPv6-shaped authority is invalid per RFC 3986
    # and rejected here rather than guessed at - the raw authority (before
    # urlparse's own bracket-stripping) is what would contain literal ":"
    # characters beyond a port separator if it were malformed this way.
    is_v6 = is_ipv6_literal(host)

    port_is_explicit = raw_port is not None
    port = raw_port if raw_port is not None else _DEFAULT_PORT_BY_SCHEME[parsed.scheme]

    return UrlComponents(
        scheme=parsed.scheme,
        host=host,
        is_ipv6=is_v6,
        port=port,
        port_is_explicit=port_is_explicit,
        path=parsed.path,
    )
