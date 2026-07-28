from __future__ import annotations

import json
import re
from typing import Any

from kingsec.application.ai.ports import AIQueryPort
from kingsec.application.ai.prompt_templates import PromptTemplates
from kingsec.application.ai.redactor import Redactor
from kingsec.domain.report import Report

_FENCE_RE = re.compile(r"^\s*```(?:json)?\s*|\s*```\s*$", re.IGNORECASE)


class ReportEnhancementService:
    """Enhances report entries with AI-generated context and recommendations."""

    def __init__(self, ai: AIQueryPort, redactor: Redactor | None = None) -> None:
        self._ai = ai
        self._redactor = redactor or Redactor()

    def enhance_report(self, report: Report) -> dict[str, Any]:
        enhanced_entries = []
        for entry in report.entries:
            user_prompt = PromptTemplates.REPORT_ENHANCEMENT.format(
                title=self._redactor.redact(entry.title),
                severity=entry.severity.label,
                description=self._redactor.redact(f"Finding with {entry.evidence_count} evidence items, "
                                                   f"{entry.recommendation_count} recommendations."),
            )
            system_prompt = (
                "You are KingSec's AI report editor. "
                "Respond with ONLY a JSON object. No prose, no markdown fences."
            )
            raw = self._ai.generate(system_prompt, user_prompt)
            parsed = self._parse(raw)
            enhanced_entries.append({
                "finding_id": entry.finding_id,
                "title": entry.title,
                "severity": entry.severity.label,
                "enhanced_description": parsed.get("enhanced_description", ""),
                "additional_context": parsed.get("additional_context", ""),
                "remediation_steps": parsed.get("remediation_steps", []),
                "references": parsed.get("references", []),
            })

        return {
            "assessment_id": report.assessment_id,
            "target": report.target,
            "verdict_headline": str(report.verdict.headline),
            "action_required": report.verdict.action_required,
            "enhanced_entries": enhanced_entries,
        }

    def _parse(self, raw: str) -> dict[str, Any]:
        stripped = _FENCE_RE.sub("", raw.strip())
        try:
            data = json.loads(stripped)
        except json.JSONDecodeError:
            return {}
        if not isinstance(data, dict):
            return {}
        return {
            "enhanced_description": str(data.get("enhanced_description") or ""),
            "additional_context": str(data.get("additional_context") or ""),
            "remediation_steps": list(data.get("remediation_steps") or []),
            "references": list(data.get("references") or []),
        }
