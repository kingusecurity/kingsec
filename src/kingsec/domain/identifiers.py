"""Typed identifiers.

Why wrap a string in a type instead of passing raw ``str`` around?
    Type safety. A function that expects an ``AssessmentId`` cannot be handed a
    ``FindingId`` (or an arbitrary string) by mistake — the type checker and the
    reader both catch it. It also gives the id a domain-meaningful name and a
    single place to enforce "ids are never empty".

Both are frozen dataclasses, so they are immutable and compare by value: two
``AssessmentId`` with the same string are equal and hash the same, which is what
we want for using them as dictionary keys.
"""

from __future__ import annotations

import uuid
from dataclasses import dataclass

from ._validation import ensure_non_empty


@dataclass(frozen=True, slots=True)
class AssessmentId:
    """Unique identifier for an :class:`Assessment`."""

    value: str

    def __post_init__(self) -> None:
        ensure_non_empty(self.value, "AssessmentId")

    @classmethod
    def generate(cls) -> "AssessmentId":
        """Create a fresh, collision-resistant id (prefixed for readability)."""

        return cls(f"asmt-{uuid.uuid4().hex}")

    def __str__(self) -> str:
        return self.value


@dataclass(frozen=True, slots=True)
class FindingId:
    """Unique identifier for a :class:`Finding`."""

    value: str

    def __post_init__(self) -> None:
        ensure_non_empty(self.value, "FindingId")

    @classmethod
    def generate(cls) -> "FindingId":
        return cls(f"find-{uuid.uuid4().hex}")

    def __str__(self) -> str:
        return self.value
