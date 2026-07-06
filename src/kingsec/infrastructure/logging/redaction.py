"""Secret redaction for structured logs.

Why this exists
    Module 2.1 stores secrets as ``SecretStr``, which masks them in every
    ``repr()``. That protects the common case. But logging is a *separate* leak
    surface: the moment someone writes ``log.info("auth", token=raw_token)`` or
    interpolates ``key.get_secret_value()`` into a message, the masking is gone.
    This processor is the defence-in-depth backstop that runs on *every* log
    event, right before rendering, and removes secrets no matter how they got
    into the event.

Three independent redaction strategies (all applied)
    1. By key name    — any field whose key looks sensitive (``password``,
                        ``api_key``, ``authorization`` ...) has its value masked
                        regardless of the value's type.
    2. By type        — any value that quacks like a secret (has a
                        ``get_secret_value`` method, i.e. pydantic ``SecretStr`` /
                        ``SecretBytes``) is masked WITHOUT ever calling that
                        method, so the real value is never materialised.
    3. By value shape — free-text strings are scanned for token-shaped
                        substrings (Bearer tokens, ``sk-...`` keys,
                        ``key=value`` secrets) and those substrings are masked.

Fail closed
    A logging call must never crash the application, and must never leak a
    secret because redaction hit an edge case. If anything in the redaction walk
    raises, we drop the original event and emit a safe marker instead.
"""

from __future__ import annotations

import re
from typing import Any

from structlog.typing import EventDict, WrappedLogger

# The token we substitute in. ASCII-only so it survives any renderer/encoding.
REDACTED = "***REDACTED***"

# Substrings that mark a *key* as sensitive. Matched case-insensitively as a
# substring, so "api_key", "X-Api-Key" and "user_api_key" all match. Chosen to
# avoid false positives on benign fields (note: we use "authorization", not a
# bare "auth", so "author" is never redacted).
_SENSITIVE_KEY_PARTS: tuple[str, ...] = (
    "password",
    "passwd",
    "secret",
    "token",
    "api_key",
    "apikey",
    "access_key",
    "private_key",
    "authorization",
    "credential",
    "cookie",
    "bearer",
    "session_key",
)

# Patterns that mask secret-shaped substrings inside free text. Kept
# conservative to minimise false positives.
#   - Bearer tokens in Authorization headers logged as strings
#   - "sk-"-style provider API keys (OpenAI / Anthropic shape)
#   - generic "<label>=<value>" / "<label>: <value>" secret assignments
_BEARER_RE = re.compile(r"(?i)\bbearer\s+[A-Za-z0-9._\-]+")
_SK_KEY_RE = re.compile(r"\bsk-[A-Za-z0-9]{12,}\b")
_ASSIGN_RE = re.compile(
    r"(?i)\b(api[_-]?key|token|password|secret)(\s*[=:]\s*)(\S+)"
)


def _key_is_sensitive(key: str) -> bool:
    lowered = key.lower()
    return any(part in lowered for part in _SENSITIVE_KEY_PARTS)


def _redact_text(value: str) -> str:
    """Mask secret-shaped substrings inside a free-text string."""

    value = _BEARER_RE.sub(REDACTED, value)
    value = _SK_KEY_RE.sub(REDACTED, value)
    # Keep the label, mask only the value part: "api_key=***REDACTED***".
    value = _ASSIGN_RE.sub(r"\1\2" + REDACTED, value)
    return value


def _redact(obj: Any) -> Any:
    """Recursively redact a value of arbitrary shape."""

    # Strategy 2: pydantic SecretStr / SecretBytes (duck-typed so we don't have
    # to import pydantic here, keeping logging decoupled from config internals).
    # We deliberately never call get_secret_value().
    if hasattr(obj, "get_secret_value"):
        return REDACTED

    if isinstance(obj, dict):
        return {
            key: (REDACTED if _key_is_sensitive(str(key)) else _redact(value))
            for key, value in obj.items()
        }

    if isinstance(obj, (list, tuple, set)):
        rebuilt = [_redact(item) for item in obj]
        return type(obj)(rebuilt) if not isinstance(obj, set) else set(rebuilt)

    if isinstance(obj, str):
        return _redact_text(obj)

    return obj


def redact_processor(
    logger: WrappedLogger, method_name: str, event_dict: EventDict
) -> EventDict:
    """structlog processor entry point. Redacts the whole event dict.

    Placed late in the chain (after contextvars are merged and exceptions are
    formatted) so it also scrubs secrets that arrived via bound context or that
    appear inside a rendered traceback string.
    """

    try:
        return _redact(event_dict)  # type: ignore[return-value]
    except Exception:  # noqa: BLE001 - logging must never raise
        # Fail closed: discard the potentially-secret-bearing event and emit a
        # safe marker so operators still see that *something* was logged.
        return {
            "event": "log_redaction_failed",
            "level": event_dict.get("level", "error"),
        }
