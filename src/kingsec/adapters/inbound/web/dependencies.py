"""FastAPI dependency injection — resolves services from the KingSec DI container.

The ``get_service`` dependency is the bridge between FastAPI's ``Depends()``
and the application's own DI container. It retrieves the ``ServiceAPI`` (or any
other port type) from the container that was wired at startup by the composition
root.

The ``get_application`` dependency exposes the ``Application`` instance itself,
which is stored on ``app.state`` by the app factory. This keeps the FastAPI
app unaware of KingSec internals — it only knows about the typed dependency.
"""

from __future__ import annotations

from fastapi import Request

from kingsec.application.ports.inbound.service_api import ServiceAPI
from kingsec.bootstrap.application import Application


def get_application(request: Request) -> Application:
    """Retrieve the wired Application from FastAPI's app state."""
    return request.app.state.kingsec_app  # type: ignore[no-any-return]


def get_service(request: Request) -> ServiceAPI:
    """Resolve the ServiceAPI port from the KingSec DI container."""
    app = get_application(request)
    return app.resolve(ServiceAPI)  # type: ignore[no-any-return]
