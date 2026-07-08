"""Unit tests for the AI response parser."""

from __future__ import annotations

import json

import pytest

from kingsec.infrastructure.ai import ResponseParser
from kingsec.infrastructure.ai.errors import AIResponseError

_VALID = {
    "title": "T",
    "explanation": "why",
    "business_impact": "impact",
    "remediation": "fix it",
    "references": ["https://a", "https://b"],
    "confidence": 0.8,
}


class TestValid:
    def test_parses_valid_json(self) -> None:
        e = ResponseParser().parse(json.dumps(_VALID))
        assert e.title == "T"
        assert e.remediation == "fix it"
        assert e.references == ("https://a", "https://b")
        assert e.confidence == 0.8

    def test_tolerates_markdown_fences(self) -> None:
        fenced = "```json\n" + json.dumps(_VALID) + "\n```"
        assert ResponseParser().parse(fenced).title == "T"

    def test_confidence_is_clamped(self) -> None:
        data = {**_VALID, "confidence": 5}
        assert ResponseParser().parse(json.dumps(data)).confidence == 1.0

    def test_non_numeric_confidence_defaults_to_zero(self) -> None:
        data = {**_VALID, "confidence": "high"}
        assert ResponseParser().parse(json.dumps(data)).confidence == 0.0


class TestInvalid:
    def test_invalid_json_raises(self) -> None:
        with pytest.raises(AIResponseError, match="not valid JSON"):
            ResponseParser().parse("this is not json {")

    def test_non_object_json_raises(self) -> None:
        with pytest.raises(AIResponseError):
            ResponseParser().parse("[1, 2, 3]")

    def test_missing_explanation_and_remediation_raises(self) -> None:
        with pytest.raises(AIResponseError, match="missing"):
            ResponseParser().parse(json.dumps({"title": "x"}))
