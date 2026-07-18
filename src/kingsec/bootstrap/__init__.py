"""KingSec application bootstrap / composition root.

Public API
    create_application(...)      -> wire config + logging + DI + exception handlers
    Application                  -> the wired, lifecycle-managed app (context mgr)
    Container                    -> the DI container type
    ExceptionHandlerRegistry     -> the boundary-translation registry type
    BootstrapError               -> composition/lifecycle failure (code KS-BOOT-001)

Layering: this is the OUTERMOST layer. It may import config, logging, and the
shared error kernel; nothing should import it except the process entrypoint.
"""

from __future__ import annotations

from .application import Application, create_application
from .container import Container
from .errors import BootstrapError
from .exception_handling import ExceptionHandlerRegistry, default_exception_handlers
from .production import (
    ProductionApplication,
    ProductionReportService,
    create_production_application,
)

# Convenience alias — reads naturally at a program entrypoint.
bootstrap = create_application

__all__ = [
    "Application",
    "BootstrapError",
    "Container",
    "ExceptionHandlerRegistry",
    "ProductionApplication",
    "ProductionReportService",
    "bootstrap",
    "create_application",
    "create_production_application",
    "default_exception_handlers",
]
