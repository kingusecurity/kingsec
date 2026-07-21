"""DI container behaviour."""

from __future__ import annotations

import pytest

from kingsec.bootstrap import BootstrapError, Container


class _ServiceA:
    pass


class _ServiceB:
    pass


class TestResolution:
    def test_register_and_resolve_instance(self) -> None:
        container = Container()
        service = _ServiceA()
        container.register_instance(_ServiceA, service)
        assert container.resolve(_ServiceA) is service

    def test_factory_is_lazy_and_cached(self) -> None:
        container = Container()
        calls = {"n": 0}

        def factory(_c: Container) -> _ServiceA:
            calls["n"] += 1
            return _ServiceA()

        container.register_factory(_ServiceA, factory)
        assert calls["n"] == 0  # not built until resolved

        first = container.resolve(_ServiceA)
        second = container.resolve(_ServiceA)
        assert first is second  # singleton cache
        assert calls["n"] == 1  # built exactly once

    def test_missing_registration_raises_bootstrap_error(self) -> None:
        container = Container()
        with pytest.raises(BootstrapError, match="no registration found"):
            container.resolve(_ServiceB)

    def test_has(self) -> None:
        container = Container()
        assert not container.has(_ServiceA)
        container.register_instance(_ServiceA, _ServiceA())
        assert container.has(_ServiceA)


class TestShutdownHooks:
    def test_hooks_run_in_lifo_order(self) -> None:
        container = Container()
        order: list[int] = []
        container.add_shutdown_hook(lambda: order.append(1))
        container.add_shutdown_hook(lambda: order.append(2))
        container.add_shutdown_hook(lambda: order.append(3))

        container.run_shutdown_hooks()
        assert order == [3, 2, 1]  # reverse registration order

    def test_failing_hook_does_not_stop_others(self) -> None:
        container = Container()
        ran: list[str] = []
        errors: list[BaseException] = []

        def boom() -> None:
            raise RuntimeError("hook failure")

        container.add_shutdown_hook(lambda: ran.append("first"))
        container.add_shutdown_hook(boom)
        container.add_shutdown_hook(lambda: ran.append("last"))

        container.run_shutdown_hooks(on_error=errors.append)

        # LIFO: last -> boom (reported) -> first. Both good hooks still ran.
        assert ran == ["last", "first"]
        assert len(errors) == 1
        assert isinstance(errors[0], RuntimeError)
