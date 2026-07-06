"""Exception handling: process hooks and boundary translation."""

from __future__ import annotations

import io
import json
import sys

from kingsec.bootstrap.exception_handling import (
    ExceptionHandlerRegistry,
    default_exception_handlers,
    install_excepthooks,
)
from kingsec.infrastructure.config.models import LoggingSettings
from kingsec.infrastructure.logging import configure_logging, get_logger
from kingsec.shared.errors import (
    ExternalServiceError,
    ServiceTimeoutError,
    ValidationError,
)


class TestExceptHooks:
    def test_uncaught_exception_is_logged_as_critical(self) -> None:
        stream = io.StringIO()
        configure_logging(LoggingSettings(level="INFO", json_format=True), stream=stream)
        logger = get_logger("kingsec.test")

        restore = install_excepthooks(logger)
        try:
            try:
                raise ValidationError("boom", context={"field": "server.port"})
            except ValidationError as exc:
                sys.excepthook(type(exc), exc, exc.__traceback__)
        finally:
            restore()

        line = json.loads(stream.getvalue().splitlines()[-1])
        assert line["level"] == "critical"
        assert line["event"] == "uncaught exception"
        assert line["error_code"] == "KS-VAL-001"

    def test_keyboard_interrupt_is_delegated(self) -> None:
        called: list[bool] = []

        # Pre-install a spy so install_excepthooks captures it as the "previous".
        sys.excepthook = lambda *a: called.append(True)  # type: ignore[assignment]
        restore = install_excepthooks(get_logger("kingsec.test"))
        try:
            sys.excepthook(KeyboardInterrupt, KeyboardInterrupt(), None)
        finally:
            restore()

        assert called == [True]                    # delegated, not swallowed

    def test_restore_puts_original_hook_back(self) -> None:
        original = sys.excepthook
        restore = install_excepthooks(get_logger("kingsec.test"))
        assert sys.excepthook is not original      # replaced
        restore()
        assert sys.excepthook is original          # restored


class TestHandlerRegistry:
    def test_mro_resolution_uses_base_handler_for_subclass(self) -> None:
        registry = ExceptionHandlerRegistry()
        registry.register(ExternalServiceError, lambda e: "external")

        # ServiceTimeoutError has no direct handler -> resolves via its base.
        assert registry.handle(ServiceTimeoutError("slow")) == "external"

    def test_more_specific_handler_wins(self) -> None:
        registry = ExceptionHandlerRegistry()
        registry.register(ExternalServiceError, lambda e: "external")
        registry.register(ServiceTimeoutError, lambda e: "timeout")
        assert registry.handle(ServiceTimeoutError("slow")) == "timeout"

    def test_unregistered_returns_none(self) -> None:
        assert ExceptionHandlerRegistry().handle(ValueError("x")) is None


class TestDefaultHandlers:
    def test_kingsec_error_translates_to_safe_dict(self) -> None:
        registry = default_exception_handlers()
        payload = registry.handle(ValidationError("internal /etc detail"))
        assert payload["error_code"] == "KS-VAL-001"
        assert "internal" not in payload["message"]   # no leak

    def test_unknown_exception_gets_generic_payload(self) -> None:
        registry = default_exception_handlers()
        payload = registry.handle(RuntimeError("stack trace detail here"))
        assert payload["error_code"] == "KS-ERR-000"
        assert "stack trace detail" not in payload["message"]  # never leaked
