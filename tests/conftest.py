"""Fixtures for logging tests.

structlog holds global configuration and contextvars persist across a process,
so every test gets a clean slate. We drive the *real* pipeline (not
structlog.testing.capture_logs, which would bypass our redaction processor) by
writing to an in-memory stream and reading it back.
"""

from __future__ import annotations

import io
import json
from collections.abc import Callable, Iterator

import pytest
import structlog

from kingsec.infrastructure.config.models import LoggingSettings
from kingsec.infrastructure.logging import clear_context, configure_logging


@pytest.fixture(autouse=True)
def reset_structlog() -> Iterator[None]:
    structlog.reset_defaults()
    clear_context()
    yield
    clear_context()
    structlog.reset_defaults()


@pytest.fixture
def stream() -> io.StringIO:
    return io.StringIO()


@pytest.fixture
def configure(stream: io.StringIO) -> Callable[..., LoggingSettings]:
    """Configure logging from real LoggingSettings, writing to the test stream."""

    def _configure(*, level: str = "INFO", json_format: bool = False) -> LoggingSettings:
        settings = LoggingSettings(level=level, json_format=json_format)
        configure_logging(settings, stream=stream)
        return settings

    return _configure


@pytest.fixture
def read_json(stream: io.StringIO) -> Callable[[], list[dict]]:
    """Parse the captured stream as one JSON object per line."""

    def _read() -> list[dict]:
        stream.seek(0)
        return [json.loads(line) for line in stream.read().splitlines() if line.strip()]

    return _read
