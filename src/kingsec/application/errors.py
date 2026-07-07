"""Application-layer errors.

Boundary policy (important architectural decision)
    * Problems with the *inputs* to a use case, or with *persistence lookups*,
      are the application layer's concern and become ``ApplicationError`` types
      (e.g. a malformed id, or an assessment that isn't stored). These are what a
      caller of a use case should expect to handle.
    * Genuine *domain-rule* violations (the authorization gate, "a report needs
      a completed assessment") are raised by the domain as ``DomainError`` and
      are allowed to PROPAGATE unchanged — they are precise signals, and a
      further-out boundary (the future web layer) will translate them into
      transport responses.

Per this module's constraint, these errors subclass the standard-library
``Exception`` only — the application layer imports nothing but the domain and the
standard library.
"""

from __future__ import annotations


class ApplicationError(Exception):
    """Base class for errors owned by the application layer."""


class InputValidationError(ApplicationError):
    """A request DTO carried invalid or malformed input."""


class AssessmentNotFoundError(ApplicationError):
    """No assessment exists for the requested identifier."""


class ReportNotFoundError(ApplicationError):
    """No report exists for the requested assessment."""
