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
import sys

import uvicorn

from kingsec import __version__
from kingsec._data_dir_notice import announce_data_dir
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
    # No subcommand (the default) starts the server, exactly as before
    # this existed — `dest="command"` stays None in that case, so
    # `kingsec --host ... --port ...` is unchanged. Only `kingsec doctor`
    # is new.
    subparsers = parser.add_subparsers(dest="command")
    doctor_parser = subparsers.add_parser(
        "doctor",
        help="Read-only scanner preflight check (see 'kingsec doctor --help')",
    )
    doctor_parser.add_argument(
        "--profile",
        default=None,
        help="Profile whose scanners gate the exit code (default: 'full-assessment')",
    )
    doctor_parser.add_argument(
        "--env-file",
        default=None,
        help="Optional .env path to load settings from",
    )
    return parser.parse_args(argv)


def main() -> None:
    """Parse CLI arguments, then either run a subcommand or serve the API."""
    args = _parse_args()

    if args.command == "doctor":
        from kingsec._doctor import DEFAULT_PROFILE_ID, run_doctor

        sys.exit(run_doctor(profile_id=args.profile or DEFAULT_PROFILE_ID, env_file=args.env_file, stream=sys.stdout))

    # Route CLI overrides through the same env vars the settings layer
    # already reads, so --host/--port are validated by the existing
    # guardrail (KINGSEC_SERVER__ALLOW_EXTERNAL_BIND) exactly like an
    # environment-supplied value — never a separate, unvalidated path.
    if args.host is not None:
        os.environ["KINGSEC_SERVER__HOST"] = args.host
    if args.port is not None:
        os.environ["KINGSEC_SERVER__PORT"] = str(args.port)

    kingsec_app = create_wired_application()
    announce_data_dir(kingsec_app.settings)

    with kingsec_app:
        fastapi_app = create_fastapi_app(kingsec_app, register_middleware=register_middleware)

        logger = get_logger("kingsec.server")
        logger.info(
            "server starting",
            host=kingsec_app.settings.server.host,
            port=kingsec_app.settings.server.port,
            data_dir=str(kingsec_app.settings.storage.data_dir),
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
