"""The Target value object: what an assessment is assessing.

A frozen value object. The domain validates only that a target is *present and
well-formed enough to be meaningful* (non-empty). Deep format validation (is
this a routable IP? a resolvable host?) is an input-validation / infrastructure
concern, not a domain rule — the domain shouldn't need DNS to construct a value.
"""

from __future__ import annotations

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


@dataclass(frozen=True, slots=True)
class Target:
    """An immutable description of the assessment's subject."""

    value: str
    type: TargetType

    def __post_init__(self) -> None:
        ensure_non_empty(self.value, "Target value")
        if not isinstance(self.type, TargetType):
            raise InvariantViolation(f"Invalid target type: {self.type}")

    def __str__(self) -> str:
        return f"{self.value} ({self.type.value})"
