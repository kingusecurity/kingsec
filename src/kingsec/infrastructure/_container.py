from __future__ import annotations

from collections.abc import Callable
from typing import Any, Protocol


class ContainerProtocol(Protocol):
    """Minimal container interface needed by provisioning functions.

    Structural subtyping keeps infrastructure decoupled from the concrete
    bootstrap ``Container`` while enabling mypy to verify attribute access.
    """

    def register_instance(self, service_type: type[Any], instance: Any) -> None: ...

    def add_shutdown_hook(self, hook: Callable[[], None]) -> None: ...

    def resolve(self, service_type: type[Any]) -> Any: ...
