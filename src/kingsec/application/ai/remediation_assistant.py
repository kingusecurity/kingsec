from __future__ import annotations

import json
import re
from collections.abc import Sequence
from typing import Any

from kingsec.application.ai.ports import AIQueryPort
from kingsec.application.ai.prompt_templates import PromptTemplates
from kingsec.application.ai.redactor import Redactor
from kingsec.domain.finding import Finding

_FENCE_RE = re.compile(r"^\s*```(?:json)?\s*|\s*```\s*$", re.IGNORECASE)


class RemediationAssistantService:
    """Generates a prioritized remediation plan from findings."""

    def __init__(self, ai: AIQueryPort, redactor: Redactor | None = None) -> None:
        self._ai = ai
        self._redactor = redactor or Redactor()

    def plan(self, findings: Sequence[Finding]) -> dict[str, Any]:
        findings_text = "\n\n".join(
            f"Finding {i + 1}:\n"
            f"  Title: {self._redactor.redact(f.title)}\n"
            f"  Severity: {f.severity.label}\n"
            f"  Description: {self._redactor.redact(f.description[:500])}"
            for i, f in enumerate(findings)
        ) if findings else "No findings."

        user_prompt = PromptTemplates.REMEDIATION_PLAN.format(findings_text=findings_text)

        system_prompt = (
            "You are KingSec's AI remediation planner. "
            "Respond with ONLY a JSON object. No prose, no markdown fences."
        )

        raw = self._ai.generate(system_prompt, user_prompt)
        return self._parse(raw)

    def _parse(self, raw: str) -> dict[str, Any]:
        stripped = _FENCE_RE.sub("", raw.strip())
        try:
            data = json.loads(stripped)
        except json.JSONDecodeError:
            return {"prioritized_fixes": []}
        fixes = []
        for fix in (data.get("prioritized_fixes") or []):
            if isinstance(fix, dict):
                fixes.append({
                    "finding_title": str(fix.get("finding_title") or ""),
                    "effort": str(fix.get("effort") or ""),
                    "risk_reduction": str(fix.get("risk_reduction") or ""),
                    "dependencies": list(fix.get("dependencies") or []),
                })
        return {"prioritized_fixes": fixes}
