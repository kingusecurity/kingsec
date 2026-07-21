"""The bridge between the exception hierarchy and structured logging.

This is how 2.3 integrates with 2.2 *without touching 2.2*. It imports only the
exception base — no structlog — so the shared kernel stays dependency-free. It
works because a structlog logger accepts arbitrary keyword fields, and because
2.2's redaction runs over every field regardless of where it came from.

Two entry points:

    log_exception(logger, exc)     -- imperative: the caller logs an error and we
                                      attach the safe structured fields + the
                                      traceback (via exc_info) in one call.

    add_exception_context(...)     -- OPTIONAL structlog processor: if you insert
                                      it into 2.2's chain, any KingSecError logged
                                      with ``exc_info=exc`` gets its code/context
                                      pulled onto the event automatically. Not
                                      wired by default (that would modify 2.2).
"""

from __future__ import annotations

from typing import Any, Protocol

from .base import KingSecError


class _SupportsLevelCall(Protocol):
    """Structural type for "a logger with .info/.error/... methods".

    Using a Protocol (not importing structlog's BoundLogger) keeps this module
    decoupled: anything shaped like a logger works, including test doubles.
    """

    def __getattr__(self, name: str) -> Any: ...  # pragma: no cover


def log_exception(
    logger: _SupportsLevelCall,
    exc: BaseException,
    *,
    event: str | None = None,
    level: str = "error",
) -> None:
    """Log ``exc`` as a structured event with its safe fields and traceback.

    Parameters
    ----------
    logger:
        A structured logger (e.g. from ``infrastructure.logging.get_logger``).
    exc:
        The exception to log. If it is a ``KingSecError`` its ``log_context()``
        fields are attached; otherwise only a generic ``error_type`` is added.
    event:
        The log message. Defaults to the exception's internal ``message`` (or
        ``str(exc)`` for non-KingSec errors).
    level:
        The logger method name to call ("error", "warning", ...).

    ``exc_info=exc`` is passed so the logging layer renders the full traceback
    (and chained cause) into the ``exception`` field. Any secret that slipped
    into the message or context is still masked by 2.2's redaction processor.
    """
    if isinstance(exc, KingSecError):
        message = event if event is not None else exc.message
        fields = exc.log_context()
    else:
        message = event if event is not None else str(exc)
        fields = {"error_type": type(exc).__name__}

    log_method = getattr(logger, level)
    log_method(message, exc_info=exc, **fields)


def add_exception_context(logger: Any, method_name: str, event_dict: dict[str, Any]) -> dict[str, Any]:
    """OPTIONAL structlog processor: auto-attach KingSecError fields.

    If ``exc_info`` in the event is a ``KingSecError`` instance, merge its safe
    fields into the event (without overwriting anything already set). Insert this
    BEFORE ``format_exc_info`` and the redaction processor in the 2.2 chain if
    you want automatic extraction. It is intentionally NOT added by default, so
    2.3 leaves Module 2.2 untouched.
    """
    exc = event_dict.get("exc_info")
    if isinstance(exc, KingSecError):
        for key, value in exc.log_context().items():
            event_dict.setdefault(key, value)
    return event_dict
