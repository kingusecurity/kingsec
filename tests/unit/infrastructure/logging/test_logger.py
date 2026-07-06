"""Logger factory: fields, renderers, level filtering, exceptions."""

from __future__ import annotations

import io
from collections.abc import Callable

from kingsec.infrastructure.logging import get_logger


class TestRequiredFields:
    def test_json_line_has_all_required_fields(
        self, configure: Callable[..., object], read_json: Callable[[], list[dict]]
    ) -> None:
        configure(json_format=True)
        get_logger("kingsec.test").info("scan started")

        (line,) = read_json()
        # Every field the requirement mandates must be present.
        assert line["event"] == "scan started"
        assert line["level"] == "info"
        assert line["logger"] == "kingsec.test"
        assert "timestamp" in line
        assert line["correlation_id"] == "-"      # defaulted when unset
        assert line["assessment_id"] == "-"


class TestRenderers:
    def test_console_renderer_contains_message(
        self, configure: Callable[..., object], stream: io.StringIO
    ) -> None:
        configure(json_format=False)
        get_logger("kingsec.test").info("hello console")

        output = stream.getvalue()
        assert "hello console" in output
        # Console mode is not JSON.
        assert not output.strip().startswith("{")

    def test_json_renderer_emits_parseable_json(
        self, configure: Callable[..., object], read_json: Callable[[], list[dict]]
    ) -> None:
        configure(json_format=True)
        get_logger("kingsec.test").warning("json line")
        (line,) = read_json()
        assert line["event"] == "json line"


class TestLevelFiltering:
    def test_below_threshold_is_dropped(
        self, configure: Callable[..., object], stream: io.StringIO
    ) -> None:
        configure(level="WARNING", json_format=True)
        log = get_logger("kingsec.test")

        log.info("should be filtered")
        assert stream.getvalue() == ""       # info < warning -> no output

        log.warning("should appear")
        assert "should appear" in stream.getvalue()


class TestExceptionRendering:
    def test_exc_info_is_rendered(
        self, configure: Callable[..., object], read_json: Callable[[], list[dict]]
    ) -> None:
        configure(json_format=True)
        log = get_logger("kingsec.test")

        try:
            raise ValueError("boom")
        except ValueError:
            log.error("operation failed", exc_info=True)

        (line,) = read_json()
        # format_exc_info produces an "exception" field with the traceback.
        assert "exception" in line
        assert "ValueError" in line["exception"]
        assert "boom" in line["exception"]
