"""FastAPI application bootstrap for the KingSec API.

Clean Architecture — the API layer depends on the Application layer
only through ports (abstract interfaces / dependency injection).
"""

from __future__ import annotations

from fastapi import FastAPI


def create_app() -> FastAPI:
    """Create and return a configured FastAPI application instance.

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

    return app
