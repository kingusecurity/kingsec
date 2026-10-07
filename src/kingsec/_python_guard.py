"""Fail-fast Python version guard for KingSec console entry points.

``pyproject.toml`` declares ``requires-python = ">=3.11"``, but pip's own
check only fires at install time — and an operator can easily end up
running a stale ``kingsec`` console script (or ``python -m kingsec``) with
whatever ``python`` happens to be first on PATH. Without this guard, an
old interpreter dies deep inside third-party imports with a confusing
traceback (or worse, half-starts). With it, every entry point —
``kingsec``, ``kingsec-migrate``, ``kingsec-bootstrap`` — fails in one
clear line before doing anything.

Policy (matches the supported range in ``docs/INSTALL.md``):
- below 3.11: hard failure, non-zero exit, human-readable message.
- 3.11–3.13: supported, silent.
- 3.14+: loud warning, but the process continues — the version is outside
  CI's tested range, and the operator deserves to know that instead of
  discovering it via a strange failure later.
"""

from __future__ import annotations

import sys
from typing import Literal

#: Minimum interpreter KingSec supports.
MINIMUM_VERSION: tuple[int, int] = (3, 11)
#: Newest interpreter covered by CI (see the build matrix in CI config).
TESTED_MAX_VERSION: tuple[int, int] = (3, 13)

SupportLevel = Literal["supported", "untested", "unsupported"]


def evaluate(version: tuple[int, int]) -> SupportLevel:
    """Classify a ``(major, minor)`` interpreter version.

    Pure function (no I/O) so the policy is unit-testable without
    spawning interpreters.
    """
    if version < MINIMUM_VERSION:
        return "unsupported"
    if version > TESTED_MAX_VERSION:
        return "untested"
    return "supported"


def ensure_supported_python(version: tuple[int, int] | None = None) -> None:
    """Enforce the interpreter policy for the current process.

    Args:
        version: ``(major, minor)`` to check; defaults to the running
            interpreter. The parameter exists for tests — callers pass
            nothing.

    Exits the process with a clear one-line message on stderr when the
    interpreter is too old; prints a loud warning (and continues) when it
    is newer than CI tests.
    """
    major, minor = version if version is not None else (sys.version_info[0], sys.version_info[1])
    found = f"{major}.{minor}"
    level = evaluate((major, minor))

    if level == "unsupported":
        print(
            f"ERROR: KingSec requires Python {MINIMUM_VERSION[0]}.{MINIMUM_VERSION[1]} or newer "
            f"(found {found}). Install a supported Python from https://www.python.org/downloads/ "
            "or point PATH at one, then re-run.",
            file=sys.stderr,
        )
        raise SystemExit(1)

    if level == "untested":
        print(
            f"WARNING: Python {found} is newer than KingSec's CI-tested range "
            f"({MINIMUM_VERSION[0]}.{MINIMUM_VERSION[1]}-{TESTED_MAX_VERSION[0]}.{TESTED_MAX_VERSION[1]}). "
            "It will probably work, but it is not a declared support target — "
            "if you hit strange behavior, retry on a tested version before reporting it.",
            file=sys.stderr,
        )
