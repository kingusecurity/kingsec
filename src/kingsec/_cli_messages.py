"""Shared, operator-facing remediation strings.

A single source for messages that must read identically wherever they
appear - the server's own startup error boundary and kingsec-bootstrap
both need to tell an operator "migrations are not applied, run
kingsec-migrate" for the same underlying condition, and a second,
independently-worded copy would drift the moment either one changes.
"""

from __future__ import annotations


def migrations_not_applied_message(detail: str | None = None) -> str:
    """The remediation message for an unmigrated database.

    Args:
        detail: Optional extra context (e.g. current/head revisions) -
            only kingsec-bootstrap's chain-head check can compute this;
            the server's own (weaker) startup check cannot, so it is
            omitted there.
    """
    suffix = f" ({detail})" if detail else ""
    return f"migrations not applied{suffix}; run 'kingsec-migrate' first"
