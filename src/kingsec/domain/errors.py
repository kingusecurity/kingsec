"""Domain errors — local to the domain, standard-library only.

Why not reuse the shared error kernel (Module 2.3)?
    The domain is the purest, innermost layer. Keeping it free of *all* outward
    imports — including our own shared kernel — means it can be reasoned about
    and tested in complete isolation, and it never learns about cross-cutting
    concerns like error codes or logging. The application layer will translate
    these ``DomainError`` types into ``KingSecError`` at the boundary later.

Two kinds of violation, because they mean different things to a caller:
    * InvariantViolation   — a value is structurally wrong (empty title, naive
                             datetime, duplicate id). The object should never
                             have existed in that shape.
    * IllegalStateTransition — the object exists and is valid, but the requested
                             operation isn't allowed from its current state
                             (e.g. starting an assessment that isn't authorized).
"""

from __future__ import annotations


class DomainError(Exception):
    """Base class for every error raised by the domain layer."""


class InvariantViolation(DomainError):
    """A domain rule about an object's *shape/content* was violated."""


class IllegalStateTransition(DomainError):
    """An operation was attempted that the object's current *state* forbids.

    Carries the offending states so callers and tests can inspect them without
    parsing the message.
    """

    def __init__(
        self,
        message: str,
        *,
        current: object | None = None,
        attempted: object | None = None,
    ) -> None:
        super().__init__(message)
        self.current = current
        self.attempted = attempted


class TargetDecompositionError(DomainError):
    """A URL Target's value cannot be broken into usable host/port components.

    Distinct from InvariantViolation: the Target itself constructed validly
    (Target._validate_format()'s URL branch only checks scheme and netloc),
    but decompose_url() found the value ambiguous or unusable for scanning -
    an embedded credential, a non-numeric or out-of-range port, or an
    unbracketed IPv6-shaped authority. Reject rather than guess in every case
    (Phase 2B Task 2 Decision 4/Section 7).
    """
