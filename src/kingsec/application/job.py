"""Job-related types for the application layer.

These are pure application-layer concepts. The domain does not know about jobs —
jobs are an application concern (how work is scheduled), not a business rule.
"""

from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True)
class JobId:
    """Type-safe wrapper for a job identifier."""

    value: str

    def __str__(self) -> str:
        return self.value

    def __repr__(self) -> str:
        return f"JobId({self.value!r})"
