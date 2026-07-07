"""The Authorization value object.

KingSec's core rule is that active work requires authorization. Authorization is
not a boolean — it's *evidence of a decision*: who authorized it, when, and over
what scope. Modelling it as a value object gives the assessment an audit trail
and makes the authorization gate meaningful (you cannot authorize anonymously).
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timezone

from ._validation import ensure_non_empty, ensure_timezone_aware


@dataclass(frozen=True, slots=True)
class Authorization:
    """Immutable proof that an assessment was authorized."""

    authorized_by: str          # who granted authorization (person / ticket)
    authorized_at: datetime     # when (timezone-aware)
    scope: str                  # what was authorized (e.g. the target/range)

    def __post_init__(self) -> None:
        ensure_non_empty(self.authorized_by, "authorized_by")
        ensure_non_empty(self.scope, "authorization scope")
        ensure_timezone_aware(self.authorized_at, "authorized_at")

    @classmethod
    def grant(cls, authorized_by: str, scope: str) -> "Authorization":
        """Create an authorization stamped at the current UTC time."""

        return cls(
            authorized_by=authorized_by,
            authorized_at=datetime.now(timezone.utc),
            scope=scope,
        )
