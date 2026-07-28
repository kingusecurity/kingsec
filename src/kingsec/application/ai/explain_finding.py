from __future__ import annotations

import json
import re
from typing import Any

from kingsec.application.ai.ports import AIQueryPort
from kingsec.application.ai.prompt_templates import PromptTemplates
from kingsec.application.ai.redactor import Redactor
from kingsec.domain.finding import Finding

_FENCE_RE = re.compile(r"^\s*```(?:json)?\s*|\s*```\s*$", re.IGNORECASE)


class ExplainFindingService:
    """Generates a plain-English explanation of a finding."""

    def __init__(self, ai: AIQueryPort, redactor: Redactor | None = None) -> None:
        self._ai = ai
        self._redactor = redactor or Redactor()

    def explain(self, finding: Finding) -> dict[str, Any]:
        evidence_text = "\n".join(
            f"- {e.summary}: {e.detail[:500]}"
            for e in finding.evidence
        ) if finding.evidence else "No evidence recorded."

        user_prompt = PromptTemplates.EXPLAIN_FINDING.format(
            title=self._redactor.redact(finding.title),
            severity=finding.severity.label,
            description=self._redactor.redact(finding.description[:2000]),
            evidence=self._redactor.redact(evidence_text[:2000]),
        )

        system_prompt = (
            "You are KingSec's AI security analyst. "
            "Respond with ONLY a JSON object. No prose, no markdown fences."
        )

        raw = self._ai.generate(system_prompt, user_prompt)
        return self._parse(raw)

    def _parse(self, raw: str) -> dict[str, Any]:
        stripped = _FENCE_RE.sub("", raw.strip())
        try:
            data = json.loads(stripped)
        except json.JSONDecodeError:
            return {
                "plain_english": raw[:500],
                "business_impact": "",
                "technical_impact": "",
                "risk": "",
                "recommendation": "",
                "cvss_score": None,
            }
        if not isinstance(data, dict):
            return {"plain_english": raw[:500]}
        return {
            "plain_english": str(data.get("plain_english") or ""),
            "business_impact": str(data.get("business_impact") or ""),
            "technical_impact": str(data.get("technical_impact") or ""),
            "risk": str(data.get("risk") or ""),
            "recommendation": str(data.get("recommendation") or ""),
            "cvss_score": data.get("cvss_score"),
        }
