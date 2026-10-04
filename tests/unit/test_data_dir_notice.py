"""kingsec._data_dir_notice — the resolved-database-path announcement.

Onboarding-fix round: before this existed, none of kingsec-migrate,
kingsec-bootstrap, or the server printed which database they resolved and
acted on - a silent fallback to the default (Path.home()/".kingsec") when
KINGSEC_STORAGE__DATA_DIR was unset produced a real, previously
unidentified incident (docs/STATUS.md, Phase 4). These tests cover
announce_data_dir() in isolation; CLAUDE.md guard: Settings is built with
an explicit tmp_path data_dir, never the real default/home directory.
"""

from __future__ import annotations

import io
from pathlib import Path

import pytest

from kingsec._data_dir_notice import announce_data_dir
from kingsec.infrastructure.config import load_settings


def _settings_pointing_at(tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
    monkeypatch.setenv("KINGSEC_STORAGE__DATA_DIR", str(tmp_path))
    monkeypatch.setenv("KINGSEC_SECRETS__ENCRYPTION_KEY", "test-fernet-key-not-real")
    monkeypatch.setenv("KINGSEC_JWT__SECRET_KEY", "test-jwt-secret-not-real")
    monkeypatch.setenv("KINGSEC_SECRETS__API_KEY_PEPPER", "test-pepper-not-real")
    return load_settings()


class TestAnnounceDataDir:
    def test_announces_the_resolved_path_when_the_env_var_is_set(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        settings = _settings_pointing_at(tmp_path, monkeypatch)
        stream = io.StringIO()

        announce_data_dir(settings, stream=stream)

        output = stream.getvalue()
        assert str(tmp_path) in output
        assert "NOTICE" not in output

    def test_loudly_flags_the_default_when_the_env_var_is_unset(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        settings = _settings_pointing_at(tmp_path, monkeypatch)
        # Simulate the unset-env-var case without touching the real
        # default: Settings already resolved against tmp_path above, so
        # removing the var now only affects announce_data_dir()'s own
        # "was it set" check - it never re-resolves the path.
        monkeypatch.delenv("KINGSEC_STORAGE__DATA_DIR", raising=False)
        stream = io.StringIO()

        announce_data_dir(settings, stream=stream)

        output = stream.getvalue()
        assert "NOTICE" in output
        assert "KINGSEC_STORAGE__DATA_DIR" in output
        assert str(tmp_path) in output

    def test_defaults_to_stderr(self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys) -> None:
        settings = _settings_pointing_at(tmp_path, monkeypatch)

        announce_data_dir(settings)

        captured = capsys.readouterr()
        assert captured.out == ""
        assert str(tmp_path) in captured.err
