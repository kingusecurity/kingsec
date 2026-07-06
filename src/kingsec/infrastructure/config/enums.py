"""Closed value sets used by the configuration models.

Why enums instead of free-form strings?
    A raw ``str`` field like ``environment: str`` accepts *any* value, so a
    typo ("prod", "prodction") silently becomes valid config and only explodes
    later, far from its cause. Modelling these as ``Enum`` members turns the set
    of legal values into a *type*. Pydantic then rejects anything outside the
    set at load time with a message that even lists the allowed options — which
    is exactly the "fail fast with a clear error" behaviour we want.

We inherit from ``str`` (``str, Enum``) so the members behave like plain
strings anywhere they are used (comparison, logging, serialisation) while still
carrying the validation guarantees of an enum.
"""

from __future__ import annotations

from enum import Enum


class Environment(str, Enum):
    """The deployment context KingSec is running in.

    This drives environment-specific safety rules (e.g. "debug must be off in
    production"). Keep the set small and explicit — three is enough.
    """

    DEVELOPMENT = "development"
    TESTING = "testing"
    PRODUCTION = "production"


class LogLevel(str, Enum):
    """Standard Python logging severities.

    Module 2.2 (structlog) will consume ``LoggingSettings.level``. We define the
    allowed levels *here*, at the configuration boundary, so an invalid level is
    caught at startup rather than when the first log line is emitted. The values
    match the names Python's ``logging`` module expects, so 2.2 can map them
    directly without a translation table.
    """

    DEBUG = "DEBUG"
    INFO = "INFO"
    WARNING = "WARNING"
    ERROR = "ERROR"
    CRITICAL = "CRITICAL"
