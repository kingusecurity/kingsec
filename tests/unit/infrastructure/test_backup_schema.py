from __future__ import annotations

from unittest.mock import MagicMock

from kingsec.infrastructure.backup.schema import ensure_backup_tables


class TestEnsureBackupTables:
    def test_creates_all_tables(self) -> None:
        mock_session = MagicMock()
        mock_session_factory = MagicMock()
        mock_session_factory.return_value.__enter__ = MagicMock(return_value=mock_session)
        mock_session_factory.return_value.__exit__ = MagicMock(return_value=False)
        ensure_backup_tables(mock_session_factory)
        assert mock_session.execute.call_count == 7
        mock_session.commit.assert_called_once()

    def test_idempotent(self) -> None:
        mock_session = MagicMock()
        mock_session_factory = MagicMock()
        mock_session_factory.return_value.__enter__ = MagicMock(return_value=mock_session)
        mock_session_factory.return_value.__exit__ = MagicMock(return_value=False)
        ensure_backup_tables(mock_session_factory)
        ensure_backup_tables(mock_session_factory)
        assert mock_session.commit.call_count == 2
