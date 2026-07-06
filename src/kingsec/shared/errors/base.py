"""The root of the KingSec exception hierarchy.

Design goals (and why each matters)
    1. Stable machine code       -> logs/dashboards/support can reference an
                                    error unambiguously, independent of wording.
    2. Two messages, not one     -> ``message`` is the rich INTERNAL detail for
                                    operators/logs; ``user_message`` is the SAFE
                                    text shown to end users. Never leak internals
                                    (paths, queries, versions) to a user — that is
                                    reconnaissance for an attacker (OWASP:
                                    "Improper Error Handling").
    3. Structured context        -> a dict of safe key/values so the error can be
                                    logged as queryable fields, not just prose.
    4. Cause preservation        -> exception chaining keeps the original error
                                    for debugging while the user still sees only
                                    the safe message.
    5. Import-time uniqueness    -> two classes can never accidentally share a
                                    code; the clash is a hard failure at import,
                                    matching the project's fail-fast philosophy.

Dependency note
    This module imports ONLY the standard library. That is deliberate: the base
    lives in the shared kernel so the domain layer can raise these errors without
    importing infrastructure. Adding a third-party import here would poison that
    property.
"""

from __future__ import annotations

from typing import Any, ClassVar

from .codes import ErrorCode


class KingSecError(Exception):
    """Base class for every KingSec error.

    Subclasses set a class-level ``code`` and (usually) a
    ``default_user_message``. Instances may add per-occurrence ``context`` and a
    ``cause``.
    """

    # Class-level defaults. Concrete subclasses override ``code`` (required to
    # be unique) and ``default_user_message`` (a safe generic fallback).
    code: ClassVar[str] = ErrorCode.UNEXPECTED
    default_user_message: ClassVar[str] = (
        "An unexpected error occurred. Please try again or contact support."
    )

    # Global code -> class map, populated at import time by __init_subclass__.
    # Enables duplicate detection and code->class lookup for docs/tooling.
    _registry: ClassVar[dict[str, type["KingSecError"]]] = {}

    def __init_subclass__(cls, **kwargs: Any) -> None:
        """Register each subclass's code and reject duplicates at import time."""

        super().__init_subclass__(**kwargs)
        # Only consider a code the subclass declares ITSELF. A subclass that
        # merely inherits its parent's code is not a new registration.
        code = cls.__dict__.get("code")
        if code is None:
            return
        existing = KingSecError._registry.get(code)
        if existing is not None and existing is not cls:
            raise ValueError(
                f"Duplicate KingSec error code {code!r}: {cls.__name__} clashes "
                f"with {existing.__name__}. Error codes must be globally unique."
            )
        KingSecError._registry[code] = cls

    def __init__(
        self,
        message: str,
        *,
        user_message: str | None = None,
        context: dict[str, Any] | None = None,
        cause: BaseException | None = None,
    ) -> None:
        """
        Parameters
        ----------
        message:
            Internal, developer-facing detail. Goes to logs. May be specific.
        user_message:
            Safe text for end users. Defaults to the class's generic message so a
            forgotten override can never accidentally leak internals.
        context:
            Safe structured metadata (e.g. {"field": "server.port"}). Copied
            defensively so later mutation of the caller's dict can't change the
            recorded error. Must not contain secrets by design — and as defence
            in depth it still passes through the logging layer's redaction.
        cause:
            The underlying exception, preserved for chaining. Equivalent to
            ``raise KingSecError(...) from cause`` but usable when you construct
            the error before raising it.
        """

        super().__init__(message)
        self.message = message
        self.user_message = (
            user_message if user_message is not None else self.default_user_message
        )
        # dict(...) copies; {} when None. Never share the caller's mutable dict.
        self.context: dict[str, Any] = dict(context) if context else {}
        if cause is not None:
            # Setting __cause__ makes tracebacks show "The above exception was
            # the direct cause of..." exactly like `raise ... from cause`.
            self.__cause__ = cause

    def log_context(self) -> dict[str, Any]:
        """Return safe, structured fields describing this error for logging.

        These fields are merged into a structured log event by the logging layer
        (Module 2.2). ``error_code`` and ``error_type`` are always present; the
        instance ``context`` is spread on top. No secrets are included by design;
        the logging layer redacts anyway as a second line of defence.
        """

        fields: dict[str, Any] = {
            "error_code": self.code,
            "error_type": type(self).__name__,
        }
        fields.update(self.context)
        return fields

    def to_dict(self) -> dict[str, str]:
        """Return a SAFE representation for an API/user response.

        Intentionally contains only the stable code and the user-safe message —
        never the internal message, context, or cause.
        """

        return {"error_code": self.code, "message": self.user_message}

    def __str__(self) -> str:
        # Prefix the code so it appears in tracebacks and plain prints too.
        return f"[{self.code}] {self.message}"

    def __repr__(self) -> str:
        return f"{type(self).__name__}(code={self.code!r}, message={self.message!r})"


# The base itself is not a subclass, so __init_subclass__ never runs for it.
# Register it manually so code->class lookup covers the whole hierarchy.
KingSecError._registry[KingSecError.code] = KingSecError


def get_exception_for_code(code: str) -> type[KingSecError] | None:
    """Look up the exception class that owns a given code (or None)."""

    return KingSecError._registry.get(code)


def registered_codes() -> dict[str, type[KingSecError]]:
    """Return a copy of the full code -> class registry (for docs/tooling)."""

    return dict(KingSecError._registry)
