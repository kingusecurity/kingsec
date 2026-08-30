"""Private helpers that turn raw request primitives into domain value objects.

This is the one place the application translates *domain* construction errors
(``InvariantViolation``) into *application* input errors (``InputValidationError``).
Doing it here keeps every use case free of repetitive try/except and gives
callers a consistent, application-level error for bad input.
"""

from __future__ import annotations

from collections.abc import Sequence

from kingsec.domain import (
    Assessment,
    AssessmentId,
    InvariantViolation,
    ScannerRunSummary,
    Target,
    TargetType,
)
from kingsec.domain.schedule import ScanSchedule
from kingsec.shared.errors import KingSecError

from .errors import ApplicationError, AssessmentNotFoundError, InputValidationError, ScheduleNotFoundError


def to_assessment_id(raw: str) -> AssessmentId:
    """Build an AssessmentId, or raise InputValidationError if malformed."""
    try:
        return AssessmentId(raw)
    except InvariantViolation as exc:
        raise InputValidationError(f"invalid assessment id: {exc}") from exc


def check_assessment_access(assessment: Assessment, requesting_user: str, is_admin: bool) -> None:
    """Raise AssessmentNotFoundError unless the caller owns this assessment or is Admin.

    Fails closed: an assessment with no recorded owner (created before
    ownership was tracked) is Admin-only, not open to everyone.
    """
    if is_admin:
        return
    if assessment.owner_id and assessment.owner_id == requesting_user:
        return
    raise AssessmentNotFoundError(str(assessment.id))


def check_schedule_access(schedule: ScanSchedule, requesting_user: str, is_admin: bool) -> None:
    """Raise ScheduleNotFoundError unless the caller owns this schedule or is Admin.

    Phase 70 / Finding KSEC-69-01: mirrors check_assessment_access()
    exactly - same fail-closed semantics (a schedule with no recorded
    owner is Admin-only, not open to everyone), and the same choice of
    exception, so a non-owner cannot distinguish "this schedule does not
    exist" from "this schedule exists but belongs to someone else" -
    both raise the identical ScheduleNotFoundError, which the web
    adapter already maps to a generic 404.
    """
    if is_admin:
        return
    if schedule.owner_user_id and schedule.owner_user_id == requesting_user:
        return
    raise ScheduleNotFoundError(f"schedule '{schedule.id}' not found")


def safe_failure_message(exc: BaseException) -> str:
    """The safe, user-facing text for an exception that failed an operation.

    KingSecError already separates rich internal detail (``message``) from
    safe user-facing text (``user_message``) - reuse that. ApplicationError
    (AssessmentNotFoundError, ExecutionPlanUnsatisfiedError, etc.) has no
    such split, but every subclass is a deliberately-authored, developer-
    controlled business-rule message, not a wrapped raw exception, so its
    str() is safe by construction. Anything else (subprocess, filesystem,
    network, or other unvetted exceptions) may carry paths, hostnames, or
    command lines the caller never validated as safe to show a user - those
    collapse to the generic default, the same fallback
    ExceptionHandlerRegistry already uses at the HTTP boundary.
    """
    if isinstance(exc, KingSecError):
        return exc.user_message
    if isinstance(exc, ApplicationError):
        return str(exc)
    return KingSecError.default_user_message


def compose_all_scanners_failed_message(failed_scanners: Sequence[ScannerRunSummary]) -> str:
    """A safe, user-facing failure_reason for an assessment where every
    attempted scanner failed.

    Names and counts only - never a per-scanner ``skipped_reason``/``error``
    string. Those are recorded by ``engine.fail_scanner()`` from a raw
    ``str(exc)`` (see execution_routes.py's own sanitization for that sink)
    and have not been run through safe_failure_message()'s split, so
    composing them in here would reopen the same class of leak Phase 03
    closed for the other two .fail() call sites. Reusing that split isn't
    applicable to per-scanner text at all under this design - the fix is to
    never interpolate it, not to sanitize and interpolate it.
    """
    names = [s.name for s in failed_scanners]
    if len(names) == 1:
        return f"The configured scanner failed to complete: {names[0]}. No results are available for this assessment."
    return (
        f"All {len(names)} configured scanners failed to complete: "
        f"{', '.join(names)}. No results are available for this assessment."
    )


def _parse_target_type(raw: str) -> TargetType:
    """Parse a target-type string into the enum, or raise InputValidationError."""
    try:
        return TargetType(raw)
    except ValueError as exc:
        allowed = ", ".join(t.value for t in TargetType)
        raise InputValidationError(f"invalid target type {raw!r}; expected one of: {allowed}") from exc


def build_target(value: str, type_raw: str) -> Target:
    """Build a validated Target from raw primitives."""
    target_type = _parse_target_type(type_raw)
    try:
        return Target(value, target_type)
    except InvariantViolation as exc:
        raise InputValidationError(str(exc)) from exc
