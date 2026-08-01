from __future__ import annotations

import asyncio
import logging
from typing import Any

from kingsec.application.ai.ports import AIQueryPort
from kingsec.application.ai.redactor import Redactor
from kingsec.application.errors import CopilotConversationNotFoundError
from kingsec.domain.copilot import CopilotConversation, PromptTemplate

from .context_builder import CopilotContextBuilder
from .ports import AuditPublisherPort, CacheServicePort, CopilotConversationRepositoryPort

logger = logging.getLogger(__name__)

# Fire-and-forget audit tasks: kept alive here because asyncio only holds a
# weak reference to scheduled tasks, so an unreferenced task can be garbage
# collected before it runs.
_pending_audit_tasks: set[asyncio.Task[None]] = set()


def _fire_audit(audit: AuditPublisherPort | None, action: str, entity_type: str, entity_id: str, metadata: dict[str, Any] | None = None) -> None:
    if audit is None:
        return
    try:
        loop = asyncio.get_running_loop()
    except RuntimeError:
        loop = None
    try:
        if loop is not None:
            task = loop.create_task(audit.publish(action, entity_type, entity_id, metadata))
            _pending_audit_tasks.add(task)
            task.add_done_callback(_on_audit_task_done)
        else:
            # Called from a synchronous route handler running in a worker
            # thread — there is no event loop to schedule a background task
            # onto, so publish inline instead.
            asyncio.run(audit.publish(action, entity_type, entity_id, metadata))
    except Exception:
        logger.warning("audit publish failed (best-effort)", exc_info=True)


def _on_audit_task_done(task: asyncio.Task[None]) -> None:
    _pending_audit_tasks.discard(task)
    if not task.cancelled() and task.exception() is not None:
        logger.exception("Audit publish failed", exc_info=task.exception())

SYSTEM_PROMPT = """You are an AI Security Copilot for KingSec, a security platform.
You help security analysts investigate findings, understand vulnerabilities, and plan remediations.
You answer questions clearly and concisely.
When discussing technical issues, explain the impact and provide actionable advice.
You NEVER make up data. You ONLY use the context provided to you.
If you don't know something, say "I don't have enough context to answer that."
Always consider the business impact alongside the technical severity."""

SUGGESTED_QUESTIONS = [
    "Why is this finding critical?",
    "Summarize this assessment.",
    "What assets are affected?",
    "Explain this CVE.",
    "What remediation is recommended?",
    "Show related attack surface.",
    "What is the risk if ignored?",
    "What compliance frameworks apply?",
]

PROMPT_TEMPLATES: list[PromptTemplate] = [
    PromptTemplate(id="explain", name="Explain", category="general",
        system_prompt=SYSTEM_PROMPT,
        user_prompt_template="Explain this security finding in plain English. Help me understand:\n- What is the issue?\n- Why does it matter?\n- What is the potential impact?\n\nContext: {context}",
        description="Plain English explanation of a finding"),
    PromptTemplate(id="summarize", name="Summarize", category="general",
        system_prompt=SYSTEM_PROMPT,
        user_prompt_template="Provide a concise summary of the following security context:\n{context}\n\nInclude:\n- Key risks\n- Affected assets\n- Recommended next steps",
        description="Concise summary of assessment or finding"),
    PromptTemplate(id="executive", name="Executive Summary", category="reporting",
        system_prompt=SYSTEM_PROMPT,
        user_prompt_template="Create an executive summary suitable for non-technical stakeholders:\n{context}\n\nFocus on:\n- Business impact\n- Risk level\n- Recommended actions\n- Compliance implications",
        description="Non-technical executive summary"),
    PromptTemplate(id="developer", name="Developer Explanation", category="technical",
        system_prompt=SYSTEM_PROMPT,
        user_prompt_template="Explain this from a developer's perspective:\n{context}\n\nInclude:\n- Root cause analysis\n- Code-level implications\n- Fix guidance\n- Testing recommendations",
        description="Technical explanation for developers"),
    PromptTemplate(id="compliance", name="Compliance Explanation", category="compliance",
        system_prompt=SYSTEM_PROMPT,
        user_prompt_template="Explain the compliance implications:\n{context}\n\nCover:\n- Relevant frameworks (PCI DSS, SOC 2, HIPAA, ISO 27001)\n- Specific requirements violated\n- Remediation needed for compliance\n- Evidence required for auditors",
        description="Compliance and regulatory context"),
    PromptTemplate(id="threat", name="Threat Analysis", category="threat",
        system_prompt=SYSTEM_PROMPT,
        user_prompt_template="Perform a threat analysis:\n{context}\n\nInclude:\n- Threat actor profile\n- Attack vectors\n- Exploitability assessment\n- MITRE ATT&CK techniques\n- Recommended defenses",
        description="Threat intelligence analysis"),
    PromptTemplate(id="incident", name="Incident Response", category="response",
        system_prompt=SYSTEM_PROMPT,
        user_prompt_template="Provide incident response guidance:\n{context}\n\nInclude:\n- Immediate containment steps\n- Investigation checklist\n- Evidence collection\n- Recovery steps\n- Post-incident recommendations",
        description="Incident response guidance"),
    PromptTemplate(id="risk", name="Risk Explanation", category="risk",
        system_prompt=SYSTEM_PROMPT,
        user_prompt_template="Explain the risk associated with:\n{context}\n\nCover:\n- Likelihood of exploitation\n- Business impact\n- CVSS score interpretation\n- Risk severity\n- Recommended risk treatment",
        description="Risk assessment explanation"),
]


class CopilotService:
    def __init__(
        self,
        ai: AIQueryPort,
        context_builder: CopilotContextBuilder,
        conversation_repo: CopilotConversationRepositoryPort,
        redactor: Redactor | None = None,
        cache: CacheServicePort | None = None,
        audit: AuditPublisherPort | None = None,
    ) -> None:
        self._ai = ai
        self._context_builder = context_builder
        self._conversation_repo = conversation_repo
        self._redactor = redactor or Redactor()
        self._cache = cache
        self._audit = audit

    def get_prompt_templates(self) -> list[dict[str, Any]]:
        return [
            {
                "id": t.id,
                "name": t.name,
                "category": t.category,
                "description": t.description,
                "is_builtin": t.is_builtin,
            }
            for t in PROMPT_TEMPLATES
        ]

    def get_prompt_template(self, template_id: str) -> PromptTemplate | None:
        for t in PROMPT_TEMPLATES:
            if t.id == template_id:
                return t
        return None

    def create_conversation(
        self,
        title: str = "New Investigation",
        assessment_id: str | None = None,
        finding_id: str | None = None,
        asset_id: str | None = None,
        cve_id: str | None = None,
        alert_id: str | None = None,
        exposure_id: str | None = None,
    ) -> CopilotConversation:
        conversation = CopilotConversation.create(
            title=title,
            assessment_id=assessment_id,
            finding_id=finding_id,
            asset_id=asset_id,
            cve_id=cve_id,
            alert_id=alert_id,
            exposure_id=exposure_id,
        )
        return self._conversation_repo.save(conversation)

    def get_conversation(self, conversation_id: str) -> CopilotConversation:
        conv = self._conversation_repo.find_by_id(conversation_id)
        if not conv:
            raise CopilotConversationNotFoundError(f"Conversation {conversation_id} not found")
        return conv

    def list_conversations(
        self,
        assessment_id: str | None = None,
        finding_id: str | None = None,
        asset_id: str | None = None,
        cve_id: str | None = None,
        limit: int = 50,
    ) -> list[CopilotConversation]:
        return self._conversation_repo.find_all(
            assessment_id=assessment_id,
            finding_id=finding_id,
            asset_id=asset_id,
            cve_id=cve_id,
            limit=limit,
        )

    def search_conversations(self, query: str, limit: int = 20) -> list[CopilotConversation]:
        return self._conversation_repo.search(query, limit)

    def ask(
        self,
        conversation_id: str,
        question: str,
        template_id: str | None = None,
    ) -> dict[str, Any]:
        conv = self.get_conversation(conversation_id)
        investigation_type = self._detect_investigation_type(conv)
        entity_id = self._get_entity_id(conv, investigation_type)

        context = self._context_builder.build_context(investigation_type, entity_id)
        context_str = self._format_context(context)

        template = self.get_prompt_template(template_id) if template_id else None

        messages: list[dict[str, str]] = []
        if template:
            messages.append({"role": "system", "content": template.system_prompt})
        else:
            messages.append({"role": "system", "content": SYSTEM_PROMPT})

        if context_str:
            messages.append({"role": "system", "content": context_str})

        for msg in conv.messages:
            messages.append({"role": msg.role, "content": msg.content})

        if template and template.user_prompt_template:
            final_question = template.user_prompt_template.replace("{context}", context_str)
            messages.append({"role": "user", "content": final_question})
        else:
            messages.append({"role": "user", "content": self._redactor.redact(question)})

        safe_messages = self._redactor.redact_messages(messages)
        answer = self._ai.chat(safe_messages)

        conv = conv.add_message("user", question)
        conv = conv.add_message("assistant", answer)
        self._conversation_repo.save(conv)

        _fire_audit(self._audit, "copilot_ask", "copilot_conversation", conversation_id,
                     {"question": question[:200], "template": template_id})

        return {
            "answer": answer,
            "question": question,
            "conversation_id": conversation_id,
            "suggested_questions": self._get_filtered_suggestions(conv),
            "context": {
                "investigation_type": investigation_type,
                "finding": context.get("finding"),
                "assessment": context.get("assessment"),
                "asset": context.get("asset"),
                "cve": context.get("cve"),
                "alert": context.get("alert"),
                "exposure": context.get("exposure"),
            },
        }

    def delete_conversation(self, conversation_id: str) -> None:
        conv = self._conversation_repo.find_by_id(conversation_id)
        if not conv:
            raise CopilotConversationNotFoundError(f"Conversation {conversation_id} not found")
        self._conversation_repo.delete(conversation_id)
        _fire_audit(self._audit, "copilot_delete", "copilot_conversation", conversation_id, {})

    def _detect_investigation_type(self, conv: CopilotConversation) -> str:
        if conv.finding_id:
            return "finding"
        if conv.assessment_id and not conv.finding_id:
            return "assessment"
        if conv.asset_id:
            return "asset"
        if conv.cve_id:
            return "cve"
        if conv.alert_id:
            return "alert"
        if conv.exposure_id:
            return "exposure"
        return "general"

    def _get_entity_id(self, conv: CopilotConversation, inv_type: str) -> str:
        mapping = {
            "finding": conv.finding_id,
            "assessment": conv.assessment_id,
            "asset": conv.asset_id,
            "cve": conv.cve_id,
            "alert": conv.alert_id,
            "exposure": conv.exposure_id,
        }
        return mapping.get(inv_type, "") or ""

    def _format_context(self, context: dict[str, Any]) -> str:
        parts: list[str] = []
        finding = context.get("finding")
        if finding:
            parts.append(f"FINDING: {finding.get('title', '')} ({finding.get('severity', '')})")
            parts.append(f"Description: {finding.get('description', '')[:500]}")

        assessment = context.get("assessment")
        if assessment:
            parts.append(f"ASSESSMENT: {assessment.get('target', '')} - {assessment.get('status', '')}")
            parts.append(f"Findings: {assessment.get('finding_count', 0)}")

        asset = context.get("asset")
        if asset:
            parts.append(f"ASSET: {asset.get('hostname', '')} ({asset.get('ip_address', '')}) - {asset.get('asset_type', '')}")

        cve = context.get("cve")
        if cve:
            parts.append(f"CVE: {cve.get('cve_code', '')} - Severity: {cve.get('severity', '')}")
            parts.append(f"Threat Score: {cve.get('threat_score', 0)} | CVSS: {cve.get('cvss_score', 0)}")
            if cve.get("is_kev"):
                parts.append("This CVE is a Known Exploited Vulnerability.")
            parts.append(f"Description: {cve.get('description', '')[:500]}")

        alert = context.get("alert")
        if alert:
            parts.append(f"ALERT: {alert.get('title', '')} ({alert.get('severity', '')}) - {alert.get('status', '')}")

        exposure = context.get("exposure")
        if exposure:
            parts.append(f"EXPOSURE: {exposure.get('exposure_type', '')} ({exposure.get('severity', '')})")

        return "\n".join(parts)

    def _get_filtered_suggestions(self, conv: CopilotConversation) -> list[str]:
        inv_type = self._detect_investigation_type(conv)
        base = SUGGESTED_QUESTIONS[:4]
        if inv_type == "finding":
            base = [
                "Why is this finding critical?",
                "What remediation is recommended?",
                "What is the risk if ignored?",
                "What compliance frameworks apply?",
            ]
        elif inv_type == "cve":
            base = [
                "Explain this CVE.",
                "What is the exploitability?",
                "What products are affected?",
                "What is the threat score?",
            ]
        elif inv_type == "alert":
            base = [
                "What triggered this alert?",
                "What assets are affected?",
                "What should I do?",
                "Is this related to other alerts?",
            ]
        return base
