"""Application composition and lifecycle."""

from __future__ import annotations

import io
import json
from collections.abc import Callable
from pathlib import Path

import pytest

from kingsec.bootstrap import Application, create_application
from kingsec.infrastructure.config import ConfigError, Settings
from kingsec.shared.errors import ValidationError


def _events(stream: io.StringIO) -> list[str]:
    return [json.loads(line)["event"] for line in stream.getvalue().splitlines() if line.strip()]


class TestComposition:
    def test_create_application_loads_settings_and_logs_init(
        self, make_app: Callable[..., Application], log_stream: io.StringIO
    ) -> None:
        app = create_application_via(make_app)
        # Config was loaded and exposed.
        assert app.settings.server.host == "127.0.0.1"
        # Settings singleton is resolvable from the container.
        assert app.resolve(Settings) is app.settings
        # Logging was configured and the init line emitted.
        assert "application initialized" in _events(log_stream)

    def test_invalid_config_fails_fast(self, monkeypatch: pytest.MonkeyPatch, log_stream: io.StringIO) -> None:
        monkeypatch.setenv("KINGSEC_SERVER__PORT", "99999")
        with pytest.raises(ConfigError):
            create_application(log_stream=log_stream, ensure_directories=False)


class TestLifecycle:
    def test_start_and_stop_emit_lifecycle_logs(
        self, make_app: Callable[..., Application], log_stream: io.StringIO
    ) -> None:
        app = create_application_via(make_app)
        app.start()
        app.stop()
        events = _events(log_stream)
        for expected in ("application starting", "application started", "application stopping", "application stopped"):
            assert expected in events

    def test_start_and_stop_are_idempotent(self, make_app: Callable[..., Application], log_stream: io.StringIO) -> None:
        app = create_application_via(make_app)
        app.start()
        app.start()  # no-op
        app.stop()
        app.stop()  # no-op
        events = _events(log_stream)
        assert events.count("application started") == 1
        assert events.count("application stopped") == 1

    def test_context_manager_runs_shutdown_hooks(
        self, make_app: Callable[..., Application], log_stream: io.StringIO
    ) -> None:
        app = create_application_via(make_app)
        torn_down: list[str] = []
        app.register_shutdown(lambda: torn_down.append("closed"))

        with app:
            assert "application started" in _events(log_stream)
        assert torn_down == ["closed"]  # ran on context exit
        assert "application stopped" in _events(log_stream)

    def test_ensure_directories_creates_data_dir(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch, log_stream: io.StringIO
    ) -> None:
        target = tmp_path / "kingsec-data"
        monkeypatch.setenv("KINGSEC_STORAGE__DATA_DIR", str(target))
        monkeypatch.setenv("KINGSEC_LOGGING__JSON_FORMAT", "true")

        app = create_application(log_stream=log_stream, ensure_directories=True)
        assert not target.exists()  # not created until start
        app.start()
        try:
            assert target.is_dir()  # created on start
        finally:
            app.stop()


class TestBoundaryTranslation:
    def test_translate_known_error_is_safe(self, make_app: Callable[..., Application]) -> None:
        app = create_application_via(make_app)
        payload = app.translate_exception(ValidationError("internal detail"))
        assert payload["error_code"] == "KS-VAL-001"
        assert "internal detail" not in payload["message"]

    def test_translate_unknown_error_is_generic(self, make_app: Callable[..., Application]) -> None:
        app = create_application_via(make_app)
        payload = app.translate_exception(ValueError("leaky detail"))
        assert payload["error_code"] == "KS-ERR-000"
        assert "leaky detail" not in payload["message"]


def create_application_via(make_app: Callable[..., Application]) -> Application:
    """Small indirection so the type checker sees a concrete Application."""
    app = make_app()
    assert isinstance(app, Application)
    return app
