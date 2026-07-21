"""Fixtures and helpers for AI unit tests."""

from __future__ import annotations

import io
import json
from collections.abc import Callable

import httpx
import pytest

from kingsec.infrastructure.config.models import LoggingSettings
from kingsec.infrastructure.logging import configure_logging


@pytest.fixture(autouse=True)
def quiet_logging() -> None:
    configure_logging(
        LoggingSettings(level="ERROR", json_format=True), stream=io.StringIO()
    )


def openai_response(enrichment: dict) -> httpx.Response:
    """An OpenAI-compatible 200 response wrapping an enrichment JSON string."""
    return httpx.Response(
        200, json={"choices": [{"message": {"content": json.dumps(enrichment)}}]}
    )


VALID_ENRICHMENT = {
    "title": "Fix SQL Injection",
    "explanation": "The parameter is injectable.",
    "business_impact": "Full data exfiltration is possible.",
    "remediation": "Use parameterised queries.",
    "references": ["https://owasp.org/www-community/attacks/SQL_Injection"],
    "confidence": 0.9,
}


def transport_from(
    handler: Callable[[httpx.Request], httpx.Response],
) -> httpx.MockTransport:
    return httpx.MockTransport(handler)


def sequence_transport(responses: list) -> httpx.MockTransport:
    """A transport that returns/raises each item in ``responses`` in turn.

    Items may be ``httpx.Response`` objects or exception instances (raised).
    """
    calls = {"n": 0}

    def handler(request: httpx.Request) -> httpx.Response:
        index = min(calls["n"], len(responses) - 1)
        calls["n"] += 1
        item = responses[index]
        if isinstance(item, Exception):
            raise item
        return item

    transport = httpx.MockTransport(handler)
    transport.calls = calls  # type: ignore[attr-defined]
    return transport
