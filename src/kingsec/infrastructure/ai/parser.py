"""Parse an AI provider's reply text into a validated enrichment.

The model is asked for a strict JSON object. This parser tolerates common
deviations (markdown code fences) and validates the result, raising
``AIResponseError`` on anything it cannot use. It produces a plain ``Enrichment``
value object; mapping to a domain ``Recommendation`` happens in the adapter,
where the finding's severity is applied (never taken from the model).
"""

from __future__ import annotations

import json
import re
from dataclasses import dataclass

from .errors import AIResponseError

_FENCE_RE = re.compile(r"^\s*```(?:json)?\s*|\s*```\s*$", re.IGNORECASE)


@dataclass(frozen=True)
class Enrichment:
    """The structured enrichment extracted from an AI response."""

    title: str
    explanation: str
    business_impact: str
    remediation: str
    references: tuple[str, ...]
    confidence: float


def _clamp_confidence(value: object) -> float:
    try:
        number = float(value)  # type: ignore[arg-type]
    except (TypeError, ValueError):
        return 0.0
    return max(0.0, min(1.0, number))


class ResponseParser:
    """Turns provider reply text into an :class:`Enrichment`."""

    def parse(self, text: str) -> Enrichment:
        """Parse and validate ``text`` as an enrichment JSON object.

        Args:
            text: The generated text extracted from the provider response.

        Returns:
            A validated :class:`Enrichment`.

        Raises:
            AIResponseError: If the text is not valid JSON or lacks usable
                content.
        """
        stripped = _FENCE_RE.sub("", text.strip())
        try:
            data = json.loads(stripped)
        except json.JSONDecodeError as exc:
            raise AIResponseError("AI response was not valid JSON", cause=exc) from exc
        if not isinstance(data, dict):
            raise AIResponseError("AI response JSON was not an object")

        explanation = str(data.get("explanation") or "").strip()
        remediation = str(data.get("remediation") or "").strip()
        # A usable enrichment must at least explain or remediate.
        if not explanation and not remediation:
            raise AIResponseError("AI response missing explanation and remediation")

        raw_refs = data.get("references")
        references = (
            tuple(str(ref).strip() for ref in raw_refs if str(ref).strip()) if isinstance(raw_refs, list) else ()
        )

        return Enrichment(
            title=str(data.get("title") or "").strip(),
            explanation=explanation,
            business_impact=str(data.get("business_impact") or "").strip(),
            remediation=remediation,
            references=references,
            confidence=_clamp_confidence(data.get("confidence")),
        )
