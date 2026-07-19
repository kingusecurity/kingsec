"""Route factories for the KingSec REST API."""

from .download import create_download_router
from .jobs import create_jobs_router
from .report import create_report_router
from .scan import create_scan_router

__all__ = [
    "create_download_router",
    "create_jobs_router",
    "create_report_router",
    "create_scan_router",
]
