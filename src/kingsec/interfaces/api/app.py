"""FastAPI application bootstrap for the KingSec API.

Clean Architecture — the API layer depends on the Application layer
only through ports (abstract interfaces / dependency injection).
"""

from __future__ import annotations

from typing import TYPE_CHECKING

from fastapi import FastAPI

if TYPE_CHECKING:
    from kingsec.application.ports import ReportServicePort, ScannerPluginRegistry, ScannerPort


def create_app(
    registry: ScannerPluginRegistry | None = None,
    scanner: ScannerPort | None = None,
    report_service: ReportServicePort | None = None,
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
    app = FastAPI(
        title="KingSec API",
        version="0.6.0",
        description="Enterprise Security Assessment Platform",
    )

    @app.get("/")
    async def root() -> dict:
        return {"name": "KingSec", "status": "running"}

    @app.get("/health")
    async def health() -> dict:
        return {"status": "healthy"}

    @app.get("/version")
    async def version() -> dict:
        return {"version": "0.6.0"}

    if registry is not None and scanner is not None:
        from kingsec.interfaces.api.routes.scan import create_scan_router
        app.include_router(create_scan_router(registry, scanner))

    if report_service is not None:
        from kingsec.interfaces.api.routes.download import create_download_router
        from kingsec.interfaces.api.routes.report import create_report_router
        app.include_router(create_report_router(report_service))
        app.include_router(create_download_router(report_service))

    from kingsec.interfaces.api.errors import register_error_handlers
    register_error_handlers(app)

    return app
