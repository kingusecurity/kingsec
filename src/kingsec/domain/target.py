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
from .errors import InvariantViolation


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

    def __str__(self) -> str:
        return f"{self.value} ({self.type.value})"
