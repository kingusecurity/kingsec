from __future__ import annotations

import os
import tempfile
from pathlib import Path

import pytest

from kingsec.infrastructure.plugin.installer import PathTraversalError, _sanitise_archive_path


class TestSanitiseArchivePath:
    def test_normal_path_allowed(self) -> None:
        with tempfile.TemporaryDirectory() as dest:
            result = _sanitise_archive_path(dest, "main.py")
            assert Path(result) == (Path(dest).resolve() / "main.py")

    def test_nested_path_allowed(self) -> None:
        with tempfile.TemporaryDirectory() as dest:
            result = _sanitise_archive_path(dest, "subdir/module.py")
            assert Path(result) == (Path(dest).resolve() / "subdir" / "module.py")

    def test_rejects_traversal_simple(self) -> None:
        with tempfile.TemporaryDirectory() as dest:
            with pytest.raises(PathTraversalError, match="escape"):
                _sanitise_archive_path(dest, "../etc/passwd")

    def test_rejects_traversal_deep(self) -> None:
        with tempfile.TemporaryDirectory() as dest:
            with pytest.raises(PathTraversalError, match="escape"):
                _sanitise_archive_path(dest, "subdir/../../etc/passwd")

    def test_rejects_absolute_path(self) -> None:
        with tempfile.TemporaryDirectory() as dest:
            with pytest.raises(PathTraversalError, match="absolute|escape"):
                _sanitise_archive_path(dest, "/etc/passwd")

    def test_rejects_windows_drive_path(self) -> None:
        with tempfile.TemporaryDirectory() as dest:
            with pytest.raises(PathTraversalError, match="absolute|Windows drive"):
                _sanitise_archive_path(dest, "C:\\Windows\\system32\\evil.dll")

    def test_rejects_windows_drive_traversal(self) -> None:
        with tempfile.TemporaryDirectory() as dest:
            with pytest.raises(PathTraversalError, match="Windows drive|escape|absolute"):
                _sanitise_archive_path(dest, "D:../../etc/passwd")
