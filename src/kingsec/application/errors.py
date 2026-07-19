from __future__ import annotations


class ApplicationError(Exception):
    """Base class for errors owned by the application layer."""


class InputValidationError(ApplicationError):
    """A request DTO carried invalid or malformed input."""


class AssessmentNotFoundError(ApplicationError):
    """No assessment exists for the requested identifier."""


class ReportNotFoundError(ApplicationError):
    """No report exists for the requested assessment."""


class ScannerPluginError(ApplicationError):
    """Base class for all scanner plugin framework errors."""


class ScannerUnavailableError(ScannerPluginError):
    def __init__(
        self,
        message: str,
        *,
        scanner_id: str | None = None,
    ) -> None:
        super().__init__(message)
        self.scanner_id = scanner_id


class ScannerConfigError(ScannerPluginError):
    """A scanner plugin received invalid configuration."""


class ScannerVersionError(ScannerPluginError):
    """A scanner plugin targets an incompatible API version."""


class ScannerDuplicateError(ScannerPluginError):
    """A scanner plugin with the same id is already registered."""


class ScannerTimeoutError(ScannerPluginError):
    """A scanner plugin exceeded its execution time limit."""


class JobNotFoundError(ApplicationError):
    """No job exists for the requested identifier."""


class IllegalJobTransitionError(ApplicationError):
    """A job state transition is not allowed by the state machine."""
