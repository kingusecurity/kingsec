from __future__ import annotations

import json
import logging
import sys
from datetime import UTC, datetime
from typing import Any

from kingsec.application.ports.outbound import LoggingPort


class StructuredLogger(LoggingPort):
    def __init__(self, name: str = "kingsec.production") -> None:
        self._logger = logging.getLogger(name)

    def _log(self, level: str, message: str, **context: Any) -> None:
        record = {
            "timestamp": datetime.now(UTC).isoformat(),
            "level": level,
            "message": message,
            "logger": self._logger.name,
            **context,
        }
        line = json.dumps(record, default=str)
        if level == "ERROR":
            self._logger.error(line)
        elif level == "WARN":
            self._logger.warning(line)
        elif level == "DEBUG":
            self._logger.debug(line)
        else:
            self._logger.info(line)

    def info(self, message: str, **context: Any) -> None:
        self._log("INFO", message, **context)

    def warn(self, message: str, **context: Any) -> None:
        self._log("WARN", message, **context)

    def error(self, message: str, **context: Any) -> None:
        self._log("ERROR", message, **context)

    def debug(self, message: str, **context: Any) -> None:
        self._log("DEBUG", message, **context)
