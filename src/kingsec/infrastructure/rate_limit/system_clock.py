from __future__ import annotations

import time

from kingsec.application.ports.outbound.clock_port import ClockPort


class SystemClock(ClockPort):
    def now(self) -> float:
        return time.time()
