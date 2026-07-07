"""Unit tests for the Unit of Work ports (abstractness)."""

from __future__ import annotations

import pytest

from kingsec.application import UnitOfWork, UnitOfWorkFactory


class TestUnitOfWorkPortsAreAbstract:
    @pytest.mark.parametrize("port", [UnitOfWork, UnitOfWorkFactory])
    def test_cannot_instantiate_abstract_port(self, port: type) -> None:
        # @abstractmethod means the abstraction itself cannot be constructed.
        with pytest.raises(TypeError):
            port()  # type: ignore[abstract]

    def test_incomplete_uow_implementation_cannot_instantiate(self) -> None:
        class HalfUoW(UnitOfWork):
            def __enter__(self):  # missing __exit__, commit, rollback
                return self

        with pytest.raises(TypeError):
            HalfUoW()  # type: ignore[abstract]
