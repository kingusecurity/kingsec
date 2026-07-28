from __future__ import annotations

import json
import re
from collections import Counter
from typing import Any

from kingsec.application.ai.ports import AIQueryPort
from kingsec.application.ai.prompt_templates import PromptTemplates
from kingsec.application.ai.redactor import Redactor
from kingsec.domain.assessment import Assessment

_FENCE_RE = re.compile(r"^\s*```(?:json)?\s*|\s*```\s*$", re.IGNORECASE)


class ExecutiveSummaryService:
    """Generates an executive summary for a completed assessment."""

    def __init__(self, ai: AIQueryPort, redactor: Redactor | None = None) -> None:
        self._ai = ai
        self._redactor = redactor or Redactor()

    def generate(self, assessment: Assessment) -> dict[str, Any]:
        findings = assessment.findings
        severity_counts = Counter(f.severity.label for f in findings)
        severity_breakdown = "\n".join(
            f"  {level}: {count}" for level, count in severity_counts.most_common()
        ) if severity_counts else "  No findings."

        top = sorted(findings, key=lambda f: f.severity, reverse=True)[:5]
        top_findings = "\n".join(
            f"- [{f.severity.label}] {self._redactor.redact(f.title[:100])}"
            for f in top
        ) if top else "  No findings."

        user_prompt = PromptTemplates.EXECUTIVE_SUMMARY.format(
            target=self._redactor.redact(str(assessment.target)),
            finding_count=len(findings),
            severity_breakdown=severity_breakdown,
            top_findings=top_findings,
        )

        system_prompt = (
            "You are KingSec's AI report writer. "
            "Respond with ONLY a JSON object. No prose, no markdown fences."
        )

        raw = self._ai.generate(system_prompt, user_prompt)
        return self._parse(raw, assessment)

    def _parse(self, raw: str, assessment: Assessment) -> dict[str, Any]:
        stripped = _FENCE_RE.sub("", raw.strip())
        try:
            data = json.loads(stripped)
        except json.JSONDecodeError:
            data = {}
        if not isinstance(data, dict):
            data = {}
        return {
            "overall_risk": str(data.get("overall_risk") or "Assessment completed."),
            "key_findings": list(data.get("key_findings") or []),
            "immediate_actions": list(data.get("immediate_actions") or []),
            "long_term_improvements": list(data.get("long_term_improvements") or []),
            "risk_score": data.get("risk_score"),
            "assessment_id": str(assessment.id),
            "target": str(assessment.target),
        }
