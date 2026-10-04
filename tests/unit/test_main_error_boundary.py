"""kingsec.__main__ - the server's startup error boundary (Phase 8 Build C c1).

Before this existed, main() had zero exception handling: a missing
migration or a missing secret both surfaced as a raw, unhandled Python
traceback to whoever started the server. These tests assert the boundary
catches the known cases with a one-line message, never lets anything
through as a traceback, and exits non-zero - without ever constructing a
real settings object or touching a real data directory (create_wired_application
is monkeypatched to raise before it resolves anything).
"""

from __future__ import annotations

import pytest

from kingsec import __main__ as main_module
from kingsec._cli_messages import migrations_not_applied_message
from kingsec.infrastructure.config import ConfigError
from kingsec.infrastructure.persistence import SchemaNotMigratedError


@pytest.fixture(autouse=True)
def _no_real_argv(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr("sys.argv", ["kingsec"])


class TestStartupErrorBoundary:
    def test_schema_not_migrated_prints_bootstraps_own_message_and_exits_nonzero(
        self, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture
    ) -> None:
        def _raise(*_a: object, **_k: object) -> None:
            raise SchemaNotMigratedError("Database schema is not up to date.\nRun:\n  alembic upgrade head")

        monkeypatch.setattr(main_module, "create_wired_application", _raise)

        with pytest.raises(SystemExit) as exc_info:
            main_module.main()

        assert exc_info.value.code == 1
        err = capsys.readouterr().err
        assert err.strip() == f"ERROR: {migrations_not_applied_message()}"
        assert "Traceback" not in err

    def test_config_error_prints_its_own_message_and_exits_nonzero(
        self, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture
    ) -> None:
        def _raise(*_a: object, **_k: object) -> None:
            raise ConfigError("KingSec configuration is invalid. Fix the following and restart:\n  - secrets.encryption_key: required")

        monkeypatch.setattr(main_module, "create_wired_application", _raise)

        with pytest.raises(SystemExit) as exc_info:
            main_module.main()

        assert exc_info.value.code == 1
        err = capsys.readouterr().err
        assert "ERROR: " in err
        assert "encryption_key" in err
        assert "Traceback" not in err

    def test_any_other_exception_still_gets_a_clean_message_not_a_traceback(
        self, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture
    ) -> None:
        def _raise(*_a: object, **_k: object) -> None:
            raise ValueError("something unrelated went wrong")

        monkeypatch.setattr(main_module, "create_wired_application", _raise)

        with pytest.raises(SystemExit) as exc_info:
            main_module.main()

        assert exc_info.value.code == 1
        err = capsys.readouterr().err
        assert err.strip() == "ERROR: something unrelated went wrong"
        assert "Traceback" not in err
