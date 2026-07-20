"""Builders for domain tests.

These helpers construct valid domain objects and assessments in specific
lifecycle states, so each test can focus on the one rule it is checking instead
of repeating multi-step setup.
"""

from __future__ import annotations

from datetime import datetime, timezone

import pytest

from kingsec.domain import (
    Assessment,
    Authorization,
    Finding,
    Severity,
    Target,
    TargetType,
)


def utc(year: int = 2026, month: int = 1, day: int = 1) -> datetime:
    """A fixed, timezone-aware timestamp for deterministic tests."""

    return datetime(year, month, day, tzinfo=timezone.utc)


@pytest.fixture
def target() -> Target:
    return Target("10.0.0.5", TargetType.IP_ADDRESS)


@pytest.fixture
def authorization() -> Authorization:
    return Authorization("pentester@kingusecurity.com", utc(), scope="10.0.0.5")


@pytest.fixture
def draft(target: Target) -> Assessment:
    return Assessment.create(target)


@pytest.fixture
def running(draft: Assessment, authorization: Authorization) -> Assessment:
    draft.authorize(authorization)
    draft.start()
    return draft


def make_finding(severity: Severity = Severity.HIGH, title: str = "SQL Injection") -> Finding:
    return Finding.create(title, "Parameter is injectable.", severity)
