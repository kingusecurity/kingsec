from __future__ import annotations

import tempfile

from kingsec.infrastructure.backup.storage import FilesystemBackupStorage


class TestFilesystemBackupStorage:
    def test_write_and_read(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            storage = FilesystemBackupStorage(tmp)
            storage.write("bkp-1", b"hello world")
            data = storage.read("bkp-1")
            assert data == b"hello world"

    def test_exists(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            storage = FilesystemBackupStorage(tmp)
            assert storage.exists("bkp-1") is False
            storage.write("bkp-1", b"data")
            assert storage.exists("bkp-1") is True

    def test_size(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            storage = FilesystemBackupStorage(tmp)
            storage.write("bkp-1", b"12345")
            assert storage.size("bkp-1") == 5

    def test_delete(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            storage = FilesystemBackupStorage(tmp)
            storage.write("bkp-1", b"data")
            assert storage.delete("bkp-1") is True
            assert storage.exists("bkp-1") is False

    def test_read_missing(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            storage = FilesystemBackupStorage(tmp)
            assert storage.read("missing") is None

    def test_delete_missing(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            storage = FilesystemBackupStorage(tmp)
            assert storage.delete("missing") is False
