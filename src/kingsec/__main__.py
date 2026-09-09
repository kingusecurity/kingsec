"""KingSec entry point — starts the local API server.

Usage::

    python -m kingsec [--host HOST] [--port PORT]
    kingsec [--host HOST] [--port PORT]
    kingsec --help
    kingsec --version

Or via the Makefile::

    make run

The server binds to loopback (127.0.0.1) by default. The host and port are
configured through the standard ``KINGSEC_SERVER__HOST`` and
``KINGSEC_SERVER__PORT`` environment variables (see ``.env.example``), or
overridden for this run via ``--host``/``--port``. Neither flag bypasses the
guardrail below — an override is applied as if it were the corresponding
environment variable, so it is validated the same way.

Security
    The server never binds to a wildcard address unless
    ``KINGSEC_SERVER__ALLOW_EXTERNAL_BIND=true`` is explicitly set. This
    guardrail is enforced by the configuration layer at startup.
"""

from __future__ import annotations

import argparse
import os

import uvicorn

from kingsec import __version__
from kingsec.adapters.inbound.web.app import create_fastapi_app
from kingsec.bootstrap.composition import create_wired_application
from kingsec.bootstrap.web import register_middleware
from kingsec.infrastructure.logging import get_logger


def _parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(prog="kingsec", description="Start the KingSec API server.")
    parser.add_argument("--version", action="version", version=f"kingsec {__version__}")
    parser.add_argument(
        "--host",
        default=None,
        help="Bind address (default: KINGSEC_SERVER__HOST, or 127.0.0.1)",
    )
    parser.add_argument(
        "--port",
        type=int,
        default=None,
        help="Bind port (default: KINGSEC_SERVER__PORT, or 8765)",
    )
    return parser.parse_args(argv)


def main() -> None:
    """Parse CLI arguments, then compose, wire, and serve the KingSec API."""
    args = _parse_args()

    # Route CLI overrides through the same env vars the settings layer
    # already reads, so --host/--port are validated by the existing
    # guardrail (KINGSEC_SERVER__ALLOW_EXTERNAL_BIND) exactly like an
    # environment-supplied value — never a separate, unvalidated path.
    if args.host is not None:
        os.environ["KINGSEC_SERVER__HOST"] = args.host
    if args.port is not None:
        os.environ["KINGSEC_SERVER__PORT"] = str(args.port)

    kingsec_app = create_wired_application()

    with kingsec_app:
        fastapi_app = create_fastapi_app(kingsec_app, register_middleware=register_middleware)

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
