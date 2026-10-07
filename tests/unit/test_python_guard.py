"""kingsec._python_guard — interpreter version policy for the CLI entry points.

Without the guard, an old interpreter dies deep inside third-party imports
with a confusing traceback (or worse, half-starts). These tests pin the
policy: <3.11 fails fast with a clear one-liner, 3.11-3.13 pass silently,
and anything newer warns loudly but continues.
"""

from __future__ import annotations

import pytest

from kingsec._python_guard import ensure_supported_python, evaluate


class TestEvaluate:
    @pytest.mark.parametrize(
        ("version", "expected"),
        [
            ((2, 7), "unsupported"),
            ((3, 9), "unsupported"),
            ((3, 10), "unsupported"),
            ((3, 11), "supported"),
            ((3, 12), "supported"),
            ((3, 13), "supported"),
            ((3, 14), "untested"),
            ((3, 15), "untested"),
            ((4, 0), "untested"),
        ],
    )
    def test_policy_boundaries(self, version: tuple[int, int], expected: str) -> None:
        assert evaluate(version) == expected


class TestEnsureSupportedPython:
    def test_unsupported_exits_nonzero_with_clear_message(self, capsys: pytest.CaptureFixture) -> None:
        with pytest.raises(SystemExit) as exc_info:
            ensure_supported_python((3, 10))

        assert exc_info.value.code == 1
        err = capsys.readouterr().err
        assert "3.11" in err  # the requirement
        assert "3.10" in err  # what was found
        assert "Traceback" not in err

    def test_supported_is_silent(self, capsys: pytest.CaptureFixture) -> None:
        ensure_supported_python((3, 12))

        assert capsys.readouterr().err == ""

    def test_untested_warns_loudly_but_continues(self, capsys: pytest.CaptureFixture) -> None:
        ensure_supported_python((3, 14))  # must not raise

        err = capsys.readouterr().err
        assert "WARNING" in err
        assert "3.14" in err
        assert "3.11" in err  # names the tested range
