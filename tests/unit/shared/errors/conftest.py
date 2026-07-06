"""Fixtures for exception tests.

Creating a KingSecError subclass has a side effect: it registers its code in the
global registry. Tests that create throwaway subclasses must not leak those into
other tests, so we snapshot the registry and restore it after each test.
"""

from __future__ import annotations

from collections.abc import Iterator

import pytest

from kingsec.shared.errors.base import KingSecError


@pytest.fixture(autouse=True)
def preserve_registry() -> Iterator[None]:
    snapshot = dict(KingSecError._registry)
    try:
        yield
    finally:
        KingSecError._registry.clear()
        KingSecError._registry.update(snapshot)
