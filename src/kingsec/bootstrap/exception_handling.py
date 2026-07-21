"""Exception handling for the composition root.

Two distinct kinds of "exception handler registration":

    1. Process-level last resort  (install_excepthooks)
       Replaces sys.excepthook and threading.excepthook so that ANY exception
       that escapes all application code is logged as a structured, redacted,
       critical event via Modules 2.2/2.3 — instead of dumping a raw traceback
       to stderr. KeyboardInterrupt is passed through untouched so Ctrl-C still
       works normally. Returns a restore() so the lifecycle can put the original
       hooks back on shutdown.

    2. Application-level boundary translation  (ExceptionHandlerRegistry)
       Maps an exception to a SAFE representation for a caller/boundary. The
       future web layer registers HTTP-status-aware handlers here; the default
       registry already turns any KingSecError into its safe to_dict() payload
       and anything else into a generic "unexpected" payload that leaks nothing.
"""

from __future__ import annotations

import sys
import threading
from collections.abc import Callable
from typing import Any

from kingsec.shared.errors import ErrorCode, KingSecError, log_exception


def install_excepthooks(logger: Any) -> Callable[[], None]:
    """Route uncaught exceptions through structured logging. Returns restore()."""
    previous_sys = sys.excepthook
    previous_thread = threading.excepthook

    def sys_hook(exc_type, exc_value, exc_tb):  # type: ignore[no-untyped-def]
        # Never swallow Ctrl-C: delegate to the original hook so the process
        # exits the way the user expects.
        if issubclass(exc_type, KeyboardInterrupt):
            previous_sys(exc_type, exc_value, exc_tb)
            return
        try:
            log_exception(logger, exc_value, event="uncaught exception", level="critical")
        except Exception:
            previous_sys(exc_type, exc_value, exc_tb)

    def thread_hook(args: threading.ExceptHookArgs) -> None:
        if issubclass(args.exc_type, KeyboardInterrupt):
            previous_thread(args)
            return
        exc = args.exc_value or args.exc_type("uncaught thread exception")
        log_exception(logger, exc, event="uncaught thread exception", level="critical")

    sys.excepthook = sys_hook
    threading.excepthook = thread_hook

    def restore() -> None:
        sys.excepthook = previous_sys
        threading.excepthook = previous_thread

    return restore


class ExceptionHandlerRegistry:
    """Maps exception types to handlers, resolving by MRO (most specific first)."""

    def __init__(self) -> None:
        self._handlers: dict[type, Callable[[BaseException], Any]] = {}

    def register(self, exc_type: type[BaseException], handler: Callable[[BaseException], Any]) -> None:
        self._handlers[exc_type] = handler

    def handler_for(self, exc: BaseException) -> Callable[[BaseException], Any] | None:
        # Walk the exception's MRO so a handler for a base category also serves
        # its subclasses (e.g. an ExternalServiceError handler covers
        # ServiceTimeoutError) unless a more specific one is registered.
        for klass in type(exc).__mro__:
            handler = self._handlers.get(klass)
            if handler is not None:
                return handler
        return None

    def handle(self, exc: BaseException) -> Any | None:
        """Return the handler's safe result, or None if nothing is registered."""
        handler = self.handler_for(exc)
        return handler(exc) if handler is not None else None


def default_exception_handlers() -> ExceptionHandlerRegistry:
    """A registry that safely translates any exception to a leak-free payload."""
    registry = ExceptionHandlerRegistry()

    # Known application errors expose their stable code + safe user message.
    registry.register(KingSecError, lambda exc: exc.to_dict())  # type: ignore[attr-defined]

    # Anything else becomes a generic, non-revealing payload. Never surface an
    # unknown exception's message to a boundary — that is how internals leak.
    registry.register(
        Exception,
        lambda _exc: {
            "error_code": ErrorCode.UNEXPECTED,
            "message": KingSecError.default_user_message,
        },
    )
    return registry
