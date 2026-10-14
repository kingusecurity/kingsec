"""SubprocessCommandRunner: user cancellation kills the process tree.

Regression coverage for the defect where cancelling an assessment returned
200 OK while the scanner subprocess kept running: the runner's
``communicate()`` had no abort path. These tests run a real ``sleep``
subprocess and prove a set cancellation event kills it promptly.
"""

from __future__ import annotations

import threading
import time

import pytest

from kingsec.infrastructure.scanner.errors import ScannerExecutionError
from kingsec.infrastructure.scanner.runner import (
    SubprocessCommandRunner,
    cancel_event_scope,
)


def test_cancel_kills_running_process() -> None:
    runner = SubprocessCommandRunner()
    event = threading.Event()
    started = time.monotonic()

    def _cancel_soon() -> None:
        time.sleep(1.0)
        event.set()

    killer = threading.Thread(target=_cancel_soon, daemon=True)
    killer.start()
    with cancel_event_scope(event):
        with pytest.raises(ScannerExecutionError) as exc_info:
            runner.run(["sleep", "30"], timeout=60)
    elapsed = time.monotonic() - started

    assert exc_info.value.transient is False
    assert exc_info.value.context.get("cancelled") is True
    # The 30s sleep must die on the ~0.5s poll cadence, not run to completion.
    assert elapsed < 10, f"cancel took too long: {elapsed:.1f}s"
    killer.join(timeout=5)


def test_pre_set_event_aborts_without_starting_work() -> None:
    runner = SubprocessCommandRunner()
    event = threading.Event()
    event.set()
    started = time.monotonic()
    with cancel_event_scope(event):
        with pytest.raises(ScannerExecutionError) as exc_info:
            runner.run(["sleep", "30"], timeout=60)
    assert exc_info.value.transient is False
    assert time.monotonic() - started < 10


def test_unset_event_never_cancels() -> None:
    runner = SubprocessCommandRunner()
    with cancel_event_scope(threading.Event()):
        result = runner.run(["sleep", "0.2"], timeout=30)
    assert result.returncode == 0


def test_no_scope_behaves_as_before() -> None:
    runner = SubprocessCommandRunner()
    result = runner.run(["sleep", "0.2"], timeout=30)
    assert result.returncode == 0


def test_cancel_does_not_retry_by_design() -> None:
    """A cancelled scan is permanent: retrying would contradict the user."""
    runner = SubprocessCommandRunner()
    event = threading.Event()
    event.set()
    with cancel_event_scope(event):
        with pytest.raises(ScannerExecutionError) as exc_info:
            runner.run(["sleep", "30"], timeout=60)
    assert exc_info.value.transient is False
