"""The single error type this module raises.

Scope note
    Module 2.1 must "fail fast with clear error messages", which means it needs
    *something* to raise. The global exception hierarchy is a separate, later
    module and is explicitly out of scope here, so we deliberately keep this to
    ONE local exception with no hierarchy of its own.

    ``ConfigError`` subclasses ``RuntimeError`` (not ``Exception`` directly)
    because a broken configuration is an unrecoverable, environment-level
    problem — the process should refuse to start, not try to handle it. When the
    global exception base lands, this class will be re-parented to inherit from
    it; nothing else about the public surface will change.
"""

from __future__ import annotations


class ConfigError(RuntimeError):
    """Raised when configuration cannot be loaded or fails validation.

    The message is intended to be shown to an operator on a failed startup, so
    it is written to be human-readable and actionable. Crucially, the message is
    assembled without echoing raw input values (see ``loader._format_...``) so a
    validation failure can never leak a secret into a crash log.
    """
