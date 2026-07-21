from __future__ import annotations

import os
import signal
from datetime import UTC, datetime

from kingsec.application.ports.outbound import LifecycleManagerPort


class LifecycleManager(LifecycleManagerPort):
    def __init__(self) -> None:
        self._started_at = datetime.now(UTC)
        self._running = True

    def shutdown(self) -> None:
        self._running = False
        try:
            os.kill(os.getpid(), signal.SIGTERM)
        except (ImportError, AttributeError, OSError):
            pass

    def restart(self) -> None:
        try:
            sighup = getattr(signal, "SIGHUP", signal.SIGTERM)
            os.kill(os.getpid(), sighup)
        except (ImportError, AttributeError, OSError):
            pass

    def is_running(self) -> bool:
        return self._running

    def uptime_seconds(self) -> float:
        return (datetime.now(UTC) - self._started_at).total_seconds()

    def get_service_status(self) -> str:
        return "running" if self._running else "stopped"
