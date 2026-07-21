"""The concrete exception categories.

A deliberately SMALL tree. Each class maps to a real KingSec failure mode and
carries (a) a stable code and (b) a safe default user message. Finer-grained
errors are added by SUBCLASSING a category (giving the subclass its own code),
not by inflating this file — that keeps ``except`` clauses meaningful and the
code catalog readable.

    KingSecError
      ├─ ConfigurationError        misconfiguration (2.1's ConfigError fits here)
      ├─ ValidationError           caller-supplied input is invalid
      ├─ AuthorizationError        action not authorized  ← core trust guardrail
      ├─ ResourceNotFoundError     requested resource is absent
      ├─ ExternalServiceError      a downstream dependency failed
      │    └─ ServiceTimeoutError  ...specifically, it timed out
      ├─ ScannerError              a scan/plugin could not complete
      └─ PersistenceError          a storage operation failed
"""

from __future__ import annotations

from .base import KingSecError
from .codes import ErrorCode


class ConfigurationError(KingSecError):
    """Configuration is missing or invalid.

    Note: Module 2.1 ships its own local ``ConfigError`` (intentionally a lone
    ``RuntimeError`` subclass so 2.1 stays independent). Re-parenting it onto
    this class is an OPTIONAL later integration; it is not done here so 2.3 does
    not modify a frozen module.
    """

    code = ErrorCode.CONFIGURATION
    default_user_message = "The application is misconfigured. Please contact your administrator."


class ValidationError(KingSecError):
    """Caller-supplied input failed validation (bad target, malformed field)."""

    code = ErrorCode.VALIDATION
    default_user_message = "The provided input is invalid. Please review and try again."


class AuthorizationError(KingSecError):
    """An action was attempted without authorization.

    This is a first-class citizen, not an afterthought: KingSec's entire trust
    model rests on the authorization gate. Scanning a target that has not been
    authorized must raise this, and the user-facing message deliberately states
    the requirement rather than any internal reason.
    """

    code = ErrorCode.AUTHORIZATION
    default_user_message = "This action has not been authorized. Confirm target authorization before continuing."


class ResourceNotFoundError(KingSecError):
    """A requested resource (assessment, report, record) does not exist."""

    code = ErrorCode.NOT_FOUND
    default_user_message = "The requested resource was not found."


class ExternalServiceError(KingSecError):
    """A downstream/external dependency failed (e.g. the AI provider).

    Deliberately generic to the USER: the fact that provider X returned HTTP 502
    is operator detail for logs (``message``/``context``), not something to
    surface verbatim.
    """

    code = ErrorCode.EXTERNAL_SERVICE
    default_user_message = "A required external service is currently unavailable. Please try again later."


class ServiceTimeoutError(ExternalServiceError):
    """A downstream/external dependency did not respond in time.

    Subclasses ExternalServiceError so callers can catch the broad category or
    the specific timeout, whichever they need.
    """

    code = ErrorCode.EXTERNAL_TIMEOUT
    default_user_message = "A required external service did not respond in time. Please try again later."


class ScannerError(KingSecError):
    """A scan or scanner plugin could not complete."""

    code = ErrorCode.SCANNER
    default_user_message = "The security scan could not be completed."


class PersistenceError(KingSecError):
    """A storage/persistence operation failed."""

    code = ErrorCode.PERSISTENCE
    default_user_message = "A storage error occurred. Please try again later."
