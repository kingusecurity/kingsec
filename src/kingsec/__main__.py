"""KingSec entry point — starts the local API server.

Usage::

    python -m kingsec

Or via the Makefile::

    make run

The server binds to loopback (127.0.0.1) by default. The host and port are
configured through the standard ``KINGSEC_SERVER__HOST`` and
``KINGSEC_SERVER__PORT`` environment variables (see ``.env.example``).

Security
    The server never binds to a wildcard address unless
    ``KINGSEC_SERVER__ALLOW_EXTERNAL_BIND=true`` is explicitly set. This
    guardrail is enforced by the configuration layer at startup.
"""

from __future__ import annotations

import uvicorn

from kingsec.adapters.inbound.web.app import create_fastapi_app
from kingsec.bootstrap.composition import create_wired_application
from kingsec.infrastructure.logging import get_logger


def main() -> None:
    """Compose, wire, and serve the KingSec API."""

    kingsec_app = create_wired_application()

    with kingsec_app:
        fastapi_app = create_fastapi_app(kingsec_app)

        logger = get_logger("kingsec.server")
        logger.info(
            "server starting",
            host=kingsec_app.settings.server.host,
            port=kingsec_app.settings.server.port,
        )

        uvicorn.run(
            fastapi_app,
            host=kingsec_app.settings.server.host,
            port=kingsec_app.settings.server.port,
            log_level="info",
            access_log=False,
        )


if __name__ == "__main__":
    main()
