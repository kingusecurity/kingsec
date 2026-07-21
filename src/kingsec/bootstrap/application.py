"""The application composition root and its lifecycle.

``create_application`` is the single wiring point: it loads configuration,
initialises logging from it, builds the DI container and exception handlers, and
returns an ``Application``. ``Application.start()`` / ``.stop()`` manage the
runtime lifecycle and are usable as a context manager.

Ordering rationale (why this exact sequence)
    1. load settings   - MUST be first. If config is invalid we fail fast with a
                         clear ConfigError to stderr, before any subsystem exists.
    2. configure logging - needs the (now valid) settings.logging.
    3. wire container / handlers - now safe to log.
    4. start(): install excepthooks + ensure directories, emit lifecycle logs.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any

from kingsec.infrastructure.config import Settings, load_settings
from kingsec.infrastructure.logging import configure_logging, get_logger

from .container import Container
from .errors import BootstrapError
from .exception_handling import (
    ExceptionHandlerRegistry,
    default_exception_handlers,
    install_excepthooks,
)


class Application:
    """A wired, lifecycle-managed KingSec application instance."""

    def __init__(
        self,
        *,
        settings: Settings,
        container: Container,
        exception_handlers: ExceptionHandlerRegistry,
        logger: Any,
        ensure_directories: bool = True,
    ) -> None:
        self._settings = settings
        self._container = container
        self._exception_handlers = exception_handlers
        self._logger = logger
        self._ensure_directories = ensure_directories
        self._restore_excepthooks: Any = None
        self._started = False
        self._stopped = False

    # --- accessors -----------------------------------------------------------
    @property
    def settings(self) -> Settings:
        return self._settings

    @property
    def container(self) -> Container:
        return self._container

    @property
    def logger(self) -> Any:
        return self._logger

    @property
    def exception_handlers(self) -> ExceptionHandlerRegistry:
        return self._exception_handlers

    def resolve(self, service_type: type) -> Any:
        """Resolve a service from the container (convenience passthrough)."""
        return self._container.resolve(service_type)

    def register_shutdown(self, hook: Any) -> None:
        """Register a teardown callback (runs LIFO on stop)."""
        self._container.add_shutdown_hook(hook)

    def translate_exception(self, exc: BaseException) -> Any:
        """Translate an exception into a safe, leak-free payload for a boundary."""
        return self._exception_handlers.handle(exc)

    # --- lifecycle -----------------------------------------------------------
    def start(self) -> Application:
        """Install runtime hooks and mark the app running. Idempotent."""
        if self._started:
            return self
        self._logger.info(
            "application starting",
            environment=self._settings.app.environment.value,
            version=self._settings.app.version,
        )
        if self._ensure_directories:
            self._create_directories(self._settings.storage.data_dir)
        # Install last, so anything above failing doesn't leave global hooks set.
        self._restore_excepthooks = install_excepthooks(self._logger)
        self._started = True
        self._logger.info("application started")
        return self

    def stop(self) -> None:
        """Tear down in reverse order and restore global hooks. Idempotent."""
        if not self._started or self._stopped:
            return
        self._logger.info("application stopping")
        # Best-effort teardown; a failing hook is logged, not fatal.
        self._container.run_shutdown_hooks(
            on_error=lambda exc: self._logger.error(
                "shutdown hook failed", error_type=type(exc).__name__
            )
        )
        if self._restore_excepthooks is not None:
            self._restore_excepthooks()
            self._restore_excepthooks = None
        self._stopped = True
        self._logger.info("application stopped")

    def _create_directories(self, data_dir: Path) -> None:
        try:
            data_dir.mkdir(parents=True, exist_ok=True)
        except OSError as exc:
            raise BootstrapError(
                f"failed to create data directory {data_dir}",
                context={"path": str(data_dir)},
                cause=exc,
            ) from exc

    # --- context manager -----------------------------------------------------
    def __enter__(self) -> Application:
        return self.start()

    def __exit__(self, *exc_info: object) -> None:
        self.stop()


def create_application(
    *,
    env_file: str | Path | None = None,
    log_stream: Any | None = None,
    ensure_directories: bool = True,
) -> Application:
    """Compose the application: config -> logging -> container -> handlers.

    Parameters
    ----------
    env_file:
        Optional .env path forwarded to Module 2.1's loader (mainly for tests).
    log_stream:
        Optional stream for logs (defaults to stdout). Injectable for tests.
    ensure_directories:
        Whether ``start()`` should create the configured data directory.
    """
    # 1. Config first — fail fast before any subsystem exists.
    settings = load_settings(env_file)

    # 2. Logging, configured from the validated settings.
    configure_logging(settings.logging, stream=log_stream)
    logger = get_logger("kingsec.bootstrap")

    # 3. DI container. Future modules register their services on this container;
    #    for now it holds the settings singleton plus teardown wiring.
    container = Container()
    container.register_instance(Settings, settings)

    # 4. Exception handlers (safe boundary translation).
    exception_handlers = default_exception_handlers()

    logger.info("application initialized")
    return Application(
        settings=settings,
        container=container,
        exception_handlers=exception_handlers,
        logger=logger,
        ensure_directories=ensure_directories,
    )
