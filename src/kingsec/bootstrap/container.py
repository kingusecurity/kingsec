"""A minimal dependency-injection container for the composition root.

Why hand-rolled, not a DI framework?
    KingSec is a modular monolith. A full DI framework adds magic, import-time
    surprises, and a learning cost that buys nothing at this size. A ~50-line
    typed container gives us the two things we actually need — singleton wiring
    and ordered teardown — with zero magic and total readability.

How it works
    * register_instance(T, obj)  -> resolve(T) returns exactly obj.
    * register_factory(T, fn)    -> resolve(T) builds once (fn(container)),
                                    caches, and returns the same instance after.
                                    Lazy: nothing is built until first resolved.
    * add_shutdown_hook(fn)      -> hooks run in REVERSE registration order on
                                    shutdown (LIFO), because later services often
                                    depend on earlier ones and must close first.
"""

from __future__ import annotations

from collections.abc import Callable
from typing import Any, TypeVar

from .errors import BootstrapError

T = TypeVar("T")


class Container:
    """A tiny, explicit, type-keyed service container."""

    def __init__(self) -> None:
        self._instances: dict[type, Any] = {}
        self._factories: dict[type, Callable[[Container], Any]] = {}
        self._shutdown_hooks: list[Callable[[], None]] = []

    def register_instance(self, service_type: type[T], instance: T) -> None:
        """Register an already-constructed singleton under its type."""
        self._instances[service_type] = instance

    def register_factory(
        self, service_type: type[T], factory: Callable[[Container], T]
    ) -> None:
        """Register a lazy factory; the result is cached as a singleton."""
        self._factories[service_type] = factory

    def resolve(self, service_type: type[T]) -> T:
        """Return the service for ``service_type``, building it lazily if needed."""
        if service_type in self._instances:
            return self._instances[service_type]
        if service_type in self._factories:
            # Build once, then cache so every caller shares one instance.
            instance = self._factories[service_type](self)
            self._instances[service_type] = instance
            return instance
        raise BootstrapError(
            f"no registration found for dependency {service_type.__name__!r}"
        )

    def has(self, service_type: type) -> bool:
        """True if a service (instance or factory) is registered for the type."""
        return service_type in self._instances or service_type in self._factories

    def add_shutdown_hook(self, hook: Callable[[], None]) -> None:
        """Register a zero-arg callback to run at shutdown (LIFO order)."""
        self._shutdown_hooks.append(hook)

    def run_shutdown_hooks(
        self, on_error: Callable[[BaseException], None] | None = None
    ) -> None:
        """Run shutdown hooks in reverse order, best-effort.

        Teardown must be resilient: one failing hook must not prevent the rest
        from running (otherwise a leaked file handle blocks a DB connection from
        closing). Failures are reported via ``on_error`` if provided, then
        swallowed so shutdown always completes.
        """
        while self._shutdown_hooks:
            hook = self._shutdown_hooks.pop()  # LIFO
            try:
                hook()
            except Exception as exc:
                if on_error is not None:
                    on_error(exc)
