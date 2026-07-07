"""Small, private validation helpers shared by the domain objects.

Underscore-prefixed module: not part of the public domain API. Centralising
these two checks keeps every entity's validation consistent and DRY. They raise
``InvariantViolation`` because a failure here means the object is being built in
an impossible shape.
"""

from __future__ import annotations

from datetime import datetime

from .errors import InvariantViolation


def ensure_non_empty(value: str, field: str) -> str:
    """Return ``value`` if it is a non-blank string, else raise."""

    if not isinstance(value, str) or not value.strip():
        raise InvariantViolation(f"{field} must be a non-empty string")
    return value


def ensure_timezone_aware(moment: datetime, field: str) -> datetime:
    """Return ``moment`` if it is a timezone-aware datetime, else raise.

    Naive datetimes are a classic source of bugs (comparisons across zones, DST
    surprises). The domain refuses them outright so every timestamp it holds is
    unambiguous.
    """

    if not isinstance(moment, datetime):
        raise InvariantViolation(f"{field} must be a datetime")
    if moment.tzinfo is None or moment.tzinfo.utcoffset(moment) is None:
        raise InvariantViolation(f"{field} must be timezone-aware (e.g. UTC)")
    return moment
