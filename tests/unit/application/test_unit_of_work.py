from __future__ import annotations

from unittest.mock import MagicMock

import pytest

from kingsec.application.ports.repositories import JobRepositoryPort
from kingsec.application.unit_of_work import UnitOfWorkPort

# ===========================================================================
# Abstractness
# ===========================================================================


class TestUnitOfWorkPortIsAbstract:
    def test_cannot_instantiate_directly(self) -> None:
        with pytest.raises(TypeError):
            UnitOfWorkPort()  # type: ignore[abstract]

    def test_incomplete_implementation_raises(self) -> None:
        class Partial(UnitOfWorkPort):
            def begin(self) -> None:
                pass

            def commit(self) -> None:
                pass

            def rollback(self) -> None:
                pass

            # missing: close

        with pytest.raises(TypeError):
            Partial()  # type: ignore[abstract]

    def test_complete_implementation_can_instantiate(self) -> None:
        class Full(UnitOfWorkPort):
            def begin(self) -> None:
                pass

            def commit(self) -> None:
                pass

            def rollback(self) -> None:
                pass

            def close(self) -> None:
                pass

            @property
            def job_repository(self) -> JobRepositoryPort:
                return MagicMock(spec=JobRepositoryPort)

        instance = Full()
        assert isinstance(instance, UnitOfWorkPort)


# ===========================================================================
# Method signatures
# ===========================================================================


class TestUnitOfWorkPortSignatures:
    def test_has_begin(self) -> None:
        assert hasattr(UnitOfWorkPort, "begin")

    def test_has_commit(self) -> None:
        assert hasattr(UnitOfWorkPort, "commit")

    def test_has_rollback(self) -> None:
        assert hasattr(UnitOfWorkPort, "rollback")

    def test_has_close(self) -> None:
        assert hasattr(UnitOfWorkPort, "close")


# ===========================================================================
# Context manager behaviour (default implementation on the ABC)
# ===========================================================================


class TestUnitOfWorkPortContextManager:
    def test_enter_calls_begin(self) -> None:
        class Tracking(UnitOfWorkPort):
            def __init__(self):
                self.calls = []

            def begin(self) -> None:
                self.calls.append("begin")

            def commit(self) -> None:
                self.calls.append("commit")

            def rollback(self) -> None:
                self.calls.append("rollback")

            def close(self) -> None:
                self.calls.append("close")

            @property
            def job_repository(self) -> JobRepositoryPort:
                return MagicMock(spec=JobRepositoryPort)

        uow = Tracking()
        with uow:
            pass
        assert "begin" in uow.calls
        assert "close" in uow.calls

    def test_clean_exit_calls_close(self) -> None:
        class Tracking(UnitOfWorkPort):
            def __init__(self):
                self.calls = []

            def begin(self) -> None:
                self.calls.append("begin")

            def commit(self) -> None:
                self.calls.append("commit")

            def rollback(self) -> None:
                self.calls.append("rollback")

            def close(self) -> None:
                self.calls.append("close")

            @property
            def job_repository(self) -> JobRepositoryPort:
                return MagicMock(spec=JobRepositoryPort)

        uow = Tracking()
        with uow:
            pass
        # On clean exit (no exception), __exit__ calls rollback then close
        assert "rollback" in uow.calls
        assert "close" in uow.calls

    def test_exception_triggers_rollback(self) -> None:
        class Tracking(UnitOfWorkPort):
            def __init__(self):
                self.calls = []

            def begin(self) -> None:
                self.calls.append("begin")

            def commit(self) -> None:
                self.calls.append("commit")

            def rollback(self) -> None:
                self.calls.append("rollback")

            def close(self) -> None:
                self.calls.append("close")

            @property
            def job_repository(self) -> JobRepositoryPort:
                return MagicMock(spec=JobRepositoryPort)

        uow = Tracking()
        with pytest.raises(RuntimeError), uow:
            raise RuntimeError("boom")
        assert "rollback" in uow.calls
        assert "close" in uow.calls
        assert "commit" not in uow.calls

    def test_exit_returns_false(self) -> None:
        class Full(UnitOfWorkPort):
            def begin(self) -> None:
                pass

            def commit(self) -> None:
                pass

            def rollback(self) -> None:
                pass

            def close(self) -> None:
                pass

            @property
            def job_repository(self) -> JobRepositoryPort:
                return MagicMock(spec=JobRepositoryPort)

        uow = Full()
        with uow as ctx:
            assert ctx is uow

    def test_enter_returns_self(self) -> None:
        class Full(UnitOfWorkPort):
            def begin(self) -> None:
                pass

            def commit(self) -> None:
                pass

            def rollback(self) -> None:
                pass

            def close(self) -> None:
                pass

            @property
            def job_repository(self) -> JobRepositoryPort:
                return MagicMock(spec=JobRepositoryPort)

        uow = Full()
        with uow as ctx:
            assert ctx is uow
