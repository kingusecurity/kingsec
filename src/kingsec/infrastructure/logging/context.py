"""Correlation and assessment context for logs.

The problem
    A single logical operation (e.g. "run assessment X") produces many log lines
    across many functions. To trace them you need a shared ID stamped on every
    line without threading it through every function signature. That is exactly
    what ``contextvars`` provides, and structlog integrates with it directly.

What we bind
    correlation_id  — one ID per request / task / operation, so all lines from
                      that operation can be grepped together.
    assessment_id   — KingSec's domain-level trace: which security assessment a
                      line belongs to. Bound for the lifetime of an assessment.

These helpers wrap ``structlog.contextvars`` so callers in the application and
infrastructure layers have a small, intention-revealing API and never import
structlog directly.
"""

from __future__ import annotations

import uuid
from collections.abc import Iterator
from contextlib import contextmanager
from typing import Any

import structlog
from structlog.typing import EventDict, WrappedLogger

CORRELATION_ID_KEY = "correlation_id"
ASSESSMENT_ID_KEY = "assessment_id"

# Shown when a line is emitted with no active context (e.g. startup logs). A
# stable sentinel keeps the JSON schema constant, which log processors downstream
# appreciate.
_UNSET = "-"


def new_correlation_id() -> str:
    """Generate a fresh, collision-resistant correlation ID."""
    return uuid.uuid4().hex


def bind_context(**values: Any) -> None:
    """Bind arbitrary key/values onto the current logging context."""
    structlog.contextvars.bind_contextvars(**values)


def bind_correlation_id(correlation_id: str | None = None) -> str:
    """Bind a correlation ID (generating one if not supplied) and return it."""
    cid = correlation_id or new_correlation_id()
    structlog.contextvars.bind_contextvars(**{CORRELATION_ID_KEY: cid})
    return cid


def bind_assessment_id(assessment_id: str) -> None:
    """Bind the current assessment ID onto the logging context."""
    structlog.contextvars.bind_contextvars(**{ASSESSMENT_ID_KEY: assessment_id})


def clear_context() -> None:
    """Remove all bound context values (call at the end of a request/task)."""
    structlog.contextvars.clear_contextvars()


@contextmanager
def logging_context(
    *,
    correlation_id: str | None = None,
    assessment_id: str | None = None,
    **extra: Any,
) -> Iterator[str]:
    """Scoped context: bind on enter, restore previous state on exit.

    Preferred over the raw ``bind_*`` helpers because it cannot leak context
    across operation boundaries — the previous state is always restored, even if
    the body raises. Yields the correlation ID in use.
    """
    cid = correlation_id or new_correlation_id()
    data: dict[str, Any] = {CORRELATION_ID_KEY: cid, **extra}
    if assessment_id is not None:
        data[ASSESSMENT_ID_KEY] = assessment_id

    # bind_contextvars returns reset tokens for exactly the keys we set, so we
    # restore precisely the previous state rather than clearing everything.
    tokens = structlog.contextvars.bind_contextvars(**data)
    try:
        yield cid
    finally:
        structlog.contextvars.reset_contextvars(**tokens)


def ensure_context_fields(
    logger: WrappedLogger, method_name: str, event_dict: EventDict
) -> EventDict:
    """Processor: guarantee correlation_id and assessment_id always appear.

    Requirement 2.2 says these fields must be *included*. Rather than hope every
    call site bound them, we default any missing one to ``"-"`` so the log
    schema is stable and predictable.
    """
    event_dict.setdefault(CORRELATION_ID_KEY, _UNSET)
    event_dict.setdefault(ASSESSMENT_ID_KEY, _UNSET)
    return event_dict
