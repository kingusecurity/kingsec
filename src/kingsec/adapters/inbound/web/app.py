"""FastAPI application factory.

Builds the FastAPI instance, wires routes, error handlers, middleware, and
stores the KingSec ``Application`` on ``app.state`` so the dependency layer
can reach it.

The factory does NOT start the KingSec application — that is the caller's
responsibility (see ``__main__.py``). This separation keeps the FastAPI
app independently testable: tests can create it with a stubbed ``ServiceAPI``
without running the full composition root.

Middleware is registered in the correct order (outermost first):
    1. GZip compression
    2. Trusted Host
    3. CORS
    4. Security Headers
    5. Correlation ID
    6. Audit Context
    7. Request Logging
    8. Rate Limiting
"""

from __future__ import annotations

from collections.abc import AsyncIterator, Callable
from contextlib import asynccontextmanager
from typing import TYPE_CHECKING, Any

from fastapi import FastAPI

from .error_handlers import register_error_handlers
from .openapi import configure_openapi
from .spa import register_spa
from .versioning import register_versioned_routes

if TYPE_CHECKING:
    from kingsec.bootstrap.application import Application


@asynccontextmanager
async def _scheduler_lifespan(kingsec_app: Application) -> AsyncIterator[None]:
    """Start/stop InProcessScheduler around the real serving lifetime.

    KSEC-92-05: `SchedulerServicePort` was registered as a lazy DI factory
    (infrastructure/scheduler/provisioning.py) but nothing in the shipped
    application ever resolved it - `.start()` was never called anywhere,
    so scheduled scans were configured but never actually triggered
    (Phase 91 KSEC-91-02). FastAPI's `lifespan` is the correct owner, not
    `Application.start()`/`.stop()`: those two run for every `wired_app`-
    based test in this repo (dozens of files) and for the admin/bootstrap
    CLI and migration-only execution, none of which should spin up a real
    background thread. `lifespan` only fires when the app is actually
    served - confirmed directly: `uvicorn.run()` always drives it (unless
    explicitly disabled, which nothing here does), while FastAPI's own
    `TestClient` only drives it when used as `with TestClient(app) as c:`
    - a style zero existing test in this repo uses (confirmed by a
    repo-wide grep), so this cannot start a thread as a side effect of an
    ordinary unit test building the app.

    No settings flag gates this: no `scheduler.enabled`-style toggle
    exists anywhere in `infrastructure/config/models.py`, and the class's
    own docstring describes always-on polling with no mention of being
    optional - there is no evidence supporting an intentional opt-out, so
    none is invented here (KSEC-92-06/Section 7's own instruction: "Do
    not add a flag merely because it seems theoretically useful").

    Fails closed: resolving `SchedulerServicePort` or calling `.start()`
    is not wrapped in a try/except here - if construction fails (e.g. a
    missing dependency registration), that exception propagates and
    FastAPI/uvicorn's lifespan startup fails, which correctly stops the
    server from ever becoming ready. Silently swallowing this exact class
    of failure is what produced the original defect; no repository
    evidence supports treating the scheduler as an optional subsystem
    that should fail open.

    `scheduler.stop()` runs in a `finally` below `yield`, so it always
    executes on the way out - including if something later in the
    request-handling lifetime raises unhandled - guaranteeing no orphan
    background thread survives past the FastAPI app's own lifetime, per
    KSEC-92-06's cleanup requirement. `InProcessScheduler.start()`/
    `.stop()` are both already idempotent (`start()` no-ops if already
    running; `stop()` no-ops if never started) - verified by direct
    reading, not modified here per "do not redesign the scheduler."
    """
    from kingsec.application.ports.outbound.scheduler_service import SchedulerServicePort

    scheduler = kingsec_app.resolve(SchedulerServicePort)
    scheduler.start()
    try:
        yield
    finally:
        scheduler.stop()


def create_fastapi_app(
    kingsec_app: Application,
    *,
    register_middleware: Callable[..., Any] | None = None,
) -> FastAPI:
    """Build a configured FastAPI application.

    Args:
        kingsec_app: A started KingSec ``Application`` instance whose
            container has a ``ServiceAPI`` registered.

    Returns:
        A ready-to-serve ``FastAPI`` instance.
    """
    settings = kingsec_app.settings

    app = FastAPI(
        title="KingSec API",
        version=settings.app.version,
        description=("Local-first, AI-augmented Attack Surface & Vulnerability Management API"),
        docs_url="/docs",
        redoc_url="/redoc",
        openapi_url="/openapi.json",
        lifespan=lambda _app: _scheduler_lifespan(kingsec_app),
    )

    # Store the KingSec application for the dependency layer.
    app.state.kingsec_app = kingsec_app

    # Configure OpenAPI specification.
    configure_openapi(app, settings.app)

    # Register middleware (order matters: last added = outermost).
    if register_middleware:
        register_middleware(app, settings)

    # Error handlers (must be registered before routes).
    register_error_handlers(app)

    # Versioned routes (v1, future v2+).
    register_versioned_routes(app)

    # Bundled frontend SPA, if one was built into this package. Must come
    # last: its catch-all fallback route would otherwise shadow anything
    # registered after it.
    register_spa(app)

    return app
