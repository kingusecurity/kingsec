"""KingSec exception system (shared kernel).

Public API
    KingSecError            -- base of the hierarchy
    ConfigurationError, ValidationError, AuthorizationError,
    ResourceNotFoundError, ExternalServiceError, ServiceTimeoutError,
    ScannerError, PersistenceError
                            -- concrete categories
    ErrorCode               -- catalog of stable code constants
    get_exception_for_code  -- code -> class lookup
    registered_codes        -- full code -> class registry (copy)
    log_exception           -- log an exception with safe structured fields
    add_exception_context   -- optional structlog processor for auto-extraction

Boundary: this package imports ONLY the standard library, so every layer
(domain, application, infrastructure) may depend on it. It depends on nothing.
"""

from __future__ import annotations

from .base import KingSecError, get_exception_for_code, registered_codes
from .codes import ErrorCode
from .exceptions import (
    AuthorizationError,
    ConfigurationError,
    ExternalServiceError,
    PersistenceError,
    ResourceNotFoundError,
    ScannerError,
    ServiceTimeoutError,
    ValidationError,
)
from .log_bridge import add_exception_context, log_exception

__all__ = [
    "AuthorizationError",
    "ConfigurationError",
    "ErrorCode",
    "ExternalServiceError",
    "KingSecError",
    "PersistenceError",
    "ResourceNotFoundError",
    "ScannerError",
    "ServiceTimeoutError",
    "ValidationError",
    "add_exception_context",
    "get_exception_for_code",
    "log_exception",
    "registered_codes",
]
