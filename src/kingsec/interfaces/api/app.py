"""FastAPI application bootstrap for the KingSec API.

Clean Architecture — the API layer depends on the Application layer
only through ports (abstract interfaces / dependency injection).
"""

from __future__ import annotations

from collections.abc import Callable
from typing import TYPE_CHECKING, Any

from fastapi import FastAPI

if TYPE_CHECKING:
    from kingsec.application.ports import (
        JobServicePort,
        ReportServicePort,
        ScannerPluginRegistry,
        ScannerPort,
        WorkerServicePort,
    )


def create_app(
    registry: ScannerPluginRegistry | None = None,
    scanner: ScannerPort | None = None,
    report_service: ReportServicePort | None = None,
    job_service: JobServicePort | None = None,
    worker_service: WorkerServicePort | None = None,
    *,
    get_current_user: Callable[..., Any] | None = None,
    app_instance: Any | None = None,
) -> FastAPI:
    """Create and return a configured FastAPI application instance.

    Args:
        registry: Optional ``ScannerPluginRegistry`` port for scanner
            listing and validation.  When ``None``, scan endpoints
            are not registered.
        scanner: Optional ``ScannerPort`` for scan execution.  When
            ``None``, scan endpoints are not registered.
        report_service: Optional ``ReportServicePort`` for report
            generation and retrieval.  When ``None``, report endpoints
            are not registered.

    Returns:
        A fully configured ``FastAPI`` instance with route mounts.
    """
    from kingsec import __version__

    app = FastAPI(
        title="KingSec API",
        version=__version__,
        description="Enterprise Security Assessment Platform",
    )

    # When an Application instance is provided, set it on app.state so that
    # auth dependencies (get_current_user, require_role, …) can resolve ports
    # from the DI container.
    if app_instance is not None:
        app.state.kingsec_app = app_instance

    @app.get("/")
    async def root() -> dict[str, Any]:
        return {"name": "KingSec", "status": "running"}

    @app.get("/health")
    async def health() -> dict[str, Any]:
        return {"status": "healthy"}

    @app.get("/version")
    async def version() -> dict[str, Any]:
        return {"version": app.version}

    if registry is not None and scanner is not None:
        from kingsec.interfaces.api.routes.profiles import create_profiles_router
        from kingsec.interfaces.api.routes.scan import create_scan_router
        from kingsec.interfaces.api.routes.scanner_discovery import (
            create_scanner_discovery_router,
        )

        app.include_router(create_scan_router(registry, scanner, get_current_user=get_current_user))
        app.include_router(
            create_scanner_discovery_router(get_current_user=get_current_user)
        )
        app.include_router(
            create_profiles_router(get_current_user=get_current_user)
        )

    if report_service is not None:
        from kingsec.interfaces.api.routes.download import create_download_router
        from kingsec.interfaces.api.routes.report import create_report_router

        app.include_router(create_report_router(report_service, get_current_user=get_current_user))
        app.include_router(create_download_router(report_service, get_current_user=get_current_user))

    if job_service is not None:
        from kingsec.interfaces.api.routes.jobs import create_jobs_router

        app.include_router(create_jobs_router(job_service, get_current_user=get_current_user))

    if worker_service is not None:
        from kingsec.interfaces.api.routes.worker import create_worker_router

        app.include_router(create_worker_router(worker_service, get_current_user=get_current_user))

    from kingsec.interfaces.api.errors import register_error_handlers

    register_error_handlers(app)

    from kingsec.interfaces.api.middleware import register_middleware

    register_middleware(app)

    return app
