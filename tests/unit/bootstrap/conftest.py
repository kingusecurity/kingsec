"""Fixtures for bootstrap tests.

Bootstrap touches global state: structlog configuration, sys.excepthook, and
threading.excepthook. Every test must leave that state exactly as it found it,
so we snapshot and restore all of it.
"""

from __future__ import annotations

import io
import os
import sys
import threading
from collections.abc import Callable, Iterator

import pytest
import structlog

from kingsec.infrastructure.logging import clear_context


@pytest.fixture(autouse=True)
def clean_global_state(monkeypatch: pytest.MonkeyPatch) -> Iterator[None]:
    for key in list(os.environ):
        if key.startswith("KINGSEC_"):
            monkeypatch.delenv(key, raising=False)

    saved_sys = sys.excepthook
    saved_thread = threading.excepthook
    structlog.reset_defaults()
    clear_context()
    try:
        yield
    finally:
        sys.excepthook = saved_sys
        threading.excepthook = saved_thread
        structlog.reset_defaults()
        clear_context()


@pytest.fixture
def log_stream() -> io.StringIO:
    return io.StringIO()


@pytest.fixture
def make_app(log_stream: io.StringIO) -> Callable[..., object]:
    """Build an application wired to JSON logging on the test stream."""
    from kingsec.bootstrap import create_application

    def _make(**overrides: object) -> object:
        # JSON logs make field assertions robust; data dirs off by default so
        # tests never write to a real home directory.
        os.environ.setdefault("KINGSEC_LOGGING__JSON_FORMAT", "true")
        params: dict = {"log_stream": log_stream, "ensure_directories": False}
        params.update(overrides)
        return create_application(**params)

    return _make
