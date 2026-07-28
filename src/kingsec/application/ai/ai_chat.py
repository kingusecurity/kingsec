from __future__ import annotations

from collections import Counter
from typing import Any, ClassVar

from kingsec.application.ai.ports import AIQueryPort
from kingsec.application.ai.prompt_templates import PromptTemplates
from kingsec.application.ai.redactor import Redactor
from kingsec.domain.assessment import Assessment


class AIChatService:
    """Multi-turn AI chat about an assessment's results."""

    SUGGESTED_QUESTIONS: ClassVar[list[str]] = [
        "What is my biggest risk?",
        "Which findings should be fixed first?",
        "Summarize this assessment.",
        "What does this severity mean?",
        "How can I improve my security posture?",
    ]

    def __init__(self, ai: AIQueryPort, redactor: Redactor | None = None) -> None:
        self._ai = ai
        self._redactor = redactor or Redactor()

    def chat(
        self,
        question: str,
        history: list[dict[str, str]],
        assessment: Assessment | None = None,
    ) -> dict[str, Any]:
        messages: list[dict[str, str]] = [{"role": "system", "content": PromptTemplates.AI_CHAT_SYSTEM}]

        if assessment is not None:
            context = self._build_assessment_context(assessment)
            messages.append({"role": "system", "content": context})

        for msg in history:
            messages.append(msg)

        messages.append({"role": "user", "content": self._redactor.redact(question)})

        safe_messages = self._redactor.redact_messages(messages)
        answer = self._ai.chat(safe_messages)

        return {
            "answer": answer,
            "question": question,
            "suggested_questions": self.SUGGESTED_QUESTIONS,
        }

    def _build_assessment_context(self, assessment: Assessment) -> str:
        findings = assessment.findings
        severity_counts = Counter(f.severity.label for f in findings)
        breakdown = "; ".join(f"{level}: {count}" for level, count in severity_counts.most_common()) or "None"

        top = sorted(findings, key=lambda f: f.severity, reverse=True)[:5]
        top_lines = "\n".join(
            f"- [{f.severity.label}] {self._redactor.redact(f.title[:100])}"
            for f in top
        ) if top else "No findings."

        return PromptTemplates.AI_CHAT_CONTEXT.format(
            target=self._redactor.redact(str(assessment.target)),
            status=assessment.status.value,
            finding_count=len(findings),
            severity_breakdown=breakdown,
            top_findings=top_lines,
        )
