"""Route factories for the KingSec REST API."""

from .report import create_report_router
from .scan import create_scan_router

__all__ = [
    "create_report_router",
    "create_scan_router",
]
