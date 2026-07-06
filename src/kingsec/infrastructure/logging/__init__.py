"""KingSec structured logging (infrastructure layer).

Public API
    configure_logging(settings, *, stream=None)  -> wire the pipeline at startup
    get_logger(name)                             -> a structured, named logger
    logging_context(...)                         -> scoped correlation/assessment
    bind_correlation_id / bind_assessment_id     -> imperative context binding
    bind_context / clear_context                 -> generic context helpers
    new_correlation_id()                         -> generate an ID
    REDACTED                                      -> the redaction marker constant

Boundary: this is infrastructure. The domain layer must not import it. Domain
code that needs to record something receives a logging port (defined later, at
the application boundary) — it never reaches in here directly.
"""

from __future__ import annotations

from .context import (
    ASSESSMENT_ID_KEY,
    CORRELATION_ID_KEY,
    bind_assessment_id,
    bind_context,
    bind_correlation_id,
    clear_context,
    logging_context,
    new_correlation_id,
)
from .logger import configure_logging, get_logger
from .redaction import REDACTED

__all__ = [
    "ASSESSMENT_ID_KEY",
    "CORRELATION_ID_KEY",
    "REDACTED",
    "bind_assessment_id",
    "bind_context",
    "bind_correlation_id",
    "clear_context",
    "configure_logging",
    "get_logger",
    "logging_context",
    "new_correlation_id",
]
