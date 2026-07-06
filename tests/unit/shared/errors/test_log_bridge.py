"""The logging bridge, incl. real end-to-end integration with Module 2.2."""

from __future__ import annotations

import io
import json
from typing import Any

from kingsec.infrastructure.config.models import LoggingSettings
from kingsec.infrastructure.logging import configure_logging, get_logger
from kingsec.shared.errors import (
    ExternalServiceError,
    ValidationError,
    add_exception_context,
    log_exception,
)


class _FakeLogger:
    """Minimal logger double that records the call it received."""

    def __init__(self) -> None:
        self.calls: list[tuple[str, str, dict[str, Any]]] = []

    def error(self, event: str, **kwargs: Any) -> None:
        self.calls.append(("error", event, kwargs))

    def warning(self, event: str, **kwargs: Any) -> None:
        self.calls.append(("warning", event, kwargs))


class TestLogContext:
    def test_fields_include_code_type_and_context(self) -> None:
        exc = ValidationError("bad port", context={"field": "server.port"})
        fields = exc.log_context()
        assert fields["error_code"] == "KS-VAL-001"
        assert fields["error_type"] == "ValidationError"
        assert fields["field"] == "server.port"


class TestLogExceptionHelper:
    def test_attaches_fields_and_exc_info(self) -> None:
        logger = _FakeLogger()
        exc = ValidationError("bad port", context={"field": "server.port"})

        log_exception(logger, exc)

        (level, event, kwargs) = logger.calls[0]
        assert level == "error"
        assert event == "bad port"                 # defaults to internal message
        assert kwargs["error_code"] == "KS-VAL-001"
        assert kwargs["field"] == "server.port"
        assert kwargs["exc_info"] is exc           # drives traceback rendering

    def test_non_kingsec_error_gets_generic_fields(self) -> None:
        logger = _FakeLogger()
        log_exception(logger, ValueError("plain"), event="unexpected")
        (_level, event, kwargs) = logger.calls[0]
        assert event == "unexpected"
        assert kwargs["error_type"] == "ValueError"

    def test_level_is_configurable(self) -> None:
        logger = _FakeLogger()
        log_exception(logger, ValidationError("x"), level="warning")
        assert logger.calls[0][0] == "warning"


class TestOptionalProcessor:
    def test_processor_merges_fields_when_exc_is_kingsec(self) -> None:
        exc = ValidationError("bad", context={"field": "server.port"})
        event_dict = add_exception_context(None, "error", {"exc_info": exc})
        assert event_dict["error_code"] == "KS-VAL-001"
        assert event_dict["field"] == "server.port"

    def test_processor_ignores_non_kingsec_exc(self) -> None:
        event_dict = add_exception_context(None, "error", {"exc_info": ValueError()})
        assert "error_code" not in event_dict

    def test_processor_does_not_overwrite_existing_keys(self) -> None:
        exc = ValidationError("bad", context={"field": "a"})
        event_dict = add_exception_context(
            None, "error", {"exc_info": exc, "field": "preset"}
        )
        assert event_dict["field"] == "preset"


class TestEndToEndWithModule22:
    """Prove 2.3 flows through the UNMODIFIED 2.2 logging layer."""

    def _configure(self, stream: io.StringIO) -> None:
        configure_logging(
            LoggingSettings(level="INFO", json_format=True), stream=stream
        )

    def test_structured_error_is_logged_with_traceback(self) -> None:
        stream = io.StringIO()
        self._configure(stream)
        log = get_logger("kingsec.test")

        try:
            raise ConnectionError("connection refused")
        except ConnectionError as original:
            exc = ExternalServiceError(
                "AI provider unreachable",
                context={"provider": "anthropic"},
                cause=original,
            )
            log_exception(log, exc)

        line = json.loads(stream.getvalue().splitlines()[-1])
        assert line["error_code"] == "KS-EXT-001"
        assert line["error_type"] == "ExternalServiceError"
        assert line["provider"] == "anthropic"
        assert line["level"] == "error"
        # Chained cause is rendered in the traceback.
        assert "ConnectionError" in line["exception"]
        assert "connection refused" in line["exception"]

    def test_secret_in_context_is_redacted_by_logging_layer(self) -> None:
        # Even if a developer WRONGLY puts a secret-shaped field in context,
        # 2.2's redaction masks it. Defence in depth across module boundaries.
        stream = io.StringIO()
        self._configure(stream)
        log = get_logger("kingsec.test")

        exc = ValidationError("bad auth", context={"api_key": "sk-SHOULDNOTLEAK123"})
        log_exception(log, exc)

        raw = stream.getvalue()
        assert "sk-SHOULDNOTLEAK123" not in raw
        line = json.loads(raw.splitlines()[-1])
        assert line["api_key"] == "***REDACTED***"
