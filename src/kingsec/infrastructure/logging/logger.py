"""Logging configuration and the logger factory.

This module assembles the structlog pipeline from the frozen
``LoggingSettings`` produced by Module 2.1 and exposes ``get_logger``.

The processor chain (order matters)
    1. merge_contextvars     - pull correlation_id / assessment_id into the event
    2. ensure_context_fields - default those IDs to "-" if unset
    3. add_log_level         - add the "level" field
    4. TimeStamper (iso/utc) - add the "timestamp" field
    5. StackInfoRenderer     - render stack_info=True when present
    6. format_exc_info       - turn exc_info into a readable "exception" field
    7. redact_processor      - MASK SECRETS (runs last, so it also scrubs the
                               rendered traceback and any context values)
    8. renderer              - ConsoleRenderer (dev) or JSONRenderer (prod)

Redaction is deliberately the last processor before rendering so nothing added
earlier can smuggle a secret past it.
"""

from __future__ import annotations

import logging
import sys
from typing import TYPE_CHECKING, Any, TextIO

import structlog

from .context import ensure_context_fields
from .redaction import redact_processor

if TYPE_CHECKING:
    # Imported for typing only. Consuming the concrete LoggingSettings from 2.1
    # without pulling it into runtime import graph keeps coupling minimal.
    from kingsec.infrastructure.config.models import LoggingSettings


def _level_to_int(level_name: str) -> int:
    """Map a LogLevel value ('INFO') to the stdlib numeric level (20).

    getLevelNamesMapping() is stdlib on Python 3.11+, which is our floor.
    """

    return logging.getLevelNamesMapping()[level_name]


def _build_processors(*, json_format: bool, colors: bool) -> list[Any]:
    processors: list[Any] = [
        structlog.contextvars.merge_contextvars,
        ensure_context_fields,
        structlog.processors.add_log_level,
        structlog.processors.TimeStamper(fmt="iso", utc=True),
        structlog.processors.StackInfoRenderer(),
        structlog.processors.format_exc_info,
        # Secrets are removed here, AFTER everything above has contributed to the
        # event dict and BEFORE the renderer serialises it.
        redact_processor,
    ]
    if json_format:
        processors.append(structlog.processors.JSONRenderer())
    else:
        processors.append(structlog.dev.ConsoleRenderer(colors=colors))
    return processors


def configure_logging(
    settings: LoggingSettings, *, stream: TextIO | None = None
) -> None:
    """Configure the global structlog pipeline from LoggingSettings.

    Call once at startup (the composition root will do this after loading
    config). Parameters:

    settings:
        The frozen LoggingSettings from Module 2.1. ``settings.level`` sets the
        minimum severity; ``settings.json_format`` chooses the renderer.
    stream:
        Where rendered lines are written. Defaults to stdout. Injectable so the
        composition root (or a test) can redirect output without monkeypatching.
    """

    target: TextIO = stream if stream is not None else sys.stdout
    # Colours only when writing to a real terminal; never in files/pipes/tests.
    colors = hasattr(target, "isatty") and target.isatty()

    structlog.configure(
        processors=_build_processors(
            json_format=settings.json_format, colors=colors
        ),
        # Efficient level filtering: calls below the threshold become no-ops
        # instead of building and discarding an event dict.
        wrapper_class=structlog.make_filtering_bound_logger(
            _level_to_int(settings.level.value)
        ),
        logger_factory=structlog.WriteLoggerFactory(file=target),
        # Cache the bound logger per call site for performance. Safe because
        # configuration is immutable for the process lifetime after startup.
        cache_logger_on_first_use=True,
    )


def get_logger(name: str) -> Any:
    """Return a structured logger tagged with its name.

    ``name`` is conventionally the module path (``__name__``). We bind it as the
    ``logger`` field so every line records its origin — satisfying the
    "logger name" requirement without relying on stdlib integration.
    """

    return structlog.get_logger(name).bind(logger=name)
