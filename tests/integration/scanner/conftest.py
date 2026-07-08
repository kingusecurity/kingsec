"""Fixtures for scanner unit tests."""

from __future__ import annotations

import io
from collections.abc import Sequence

import pytest

from kingsec.infrastructure.config.models import LoggingSettings
from kingsec.infrastructure.logging import configure_logging
from kingsec.infrastructure.scanner.runner import CommandResult


@pytest.fixture(autouse=True)
def quiet_logging() -> None:
    configure_logging(
        LoggingSettings(level="ERROR", json_format=True), stream=io.StringIO()
    )


class FakeRunner:
    """A CommandRunner double that returns a preset result and records calls."""

    def __init__(self, result: CommandResult | None = None) -> None:
        self.result = result or CommandResult(0, "", "", 0.0)
        self.calls: list[tuple[list[str], float]] = []
        self.exception: Exception | None = None

    def run(self, args: Sequence[str], *, timeout: float) -> CommandResult:
        self.calls.append((list(args), timeout))
        if self.exception is not None:
            raise self.exception
        return self.result


@pytest.fixture
def fake_runner() -> FakeRunner:
    return FakeRunner()
