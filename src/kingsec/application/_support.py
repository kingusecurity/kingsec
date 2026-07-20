"""Private helpers that turn raw request primitives into domain value objects.

This is the one place the application translates *domain* construction errors
(``InvariantViolation``) into *application* input errors (``InputValidationError``).
Doing it here keeps every use case free of repetitive try/except and gives
callers a consistent, application-level error for bad input.
"""

from __future__ import annotations

from kingsec.domain import (
    AssessmentId,
    InvariantViolation,
    Target,
    TargetType,
)

from .errors import InputValidationError


def to_assessment_id(raw: str) -> AssessmentId:
    """Build an AssessmentId, or raise InputValidationError if malformed."""
    try:
        return AssessmentId(raw)
    except InvariantViolation as exc:
        raise InputValidationError(f"invalid assessment id: {exc}") from exc


def _parse_target_type(raw: str) -> TargetType:
    """Parse a target-type string into the enum, or raise InputValidationError."""
    try:
        return TargetType(raw)
    except ValueError as exc:
        allowed = ", ".join(t.value for t in TargetType)
        raise InputValidationError(
            f"invalid target type {raw!r}; expected one of: {allowed}"
        ) from exc


def build_target(value: str, type_raw: str) -> Target:
    """Build a validated Target from raw primitives."""
    target_type = _parse_target_type(type_raw)
    try:
        return Target(value, target_type)
    except InvariantViolation as exc:
        raise InputValidationError(str(exc)) from exc
