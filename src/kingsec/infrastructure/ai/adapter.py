"""The AI implementation of the application ``AIPort``.

Composes the prompt builder, provider strategy, HTTP client, and response parser
to turn one finding into an enriched domain ``Recommendation``. Severity is never
taken from the model — the recommendation's priority is always the finding's own
severity. Failures raise ``AIError``; the ``StartAssessment`` use case already
treats enrichment as best-effort, so an AI outage never fails a scan.
"""

from __future__ import annotations

from typing import TYPE_CHECKING

from kingsec.application import AIPort
from kingsec.domain import Finding, Recommendation
from kingsec.infrastructure.logging import get_logger

from .client import AIClient
from .errors import AIAuthenticationError
from .parser import Enrichment, ResponseParser
from .prompt import PromptBuilder
from .providers import ProviderConfig

if TYPE_CHECKING:  # typing only; no runtime import of config internals
    from kingsec.infrastructure.config.models import AISettings

_logger = get_logger("kingsec.infrastructure.ai")


class AIProviderAdapter(AIPort):
    """Enriches a finding with AI-generated remediation guidance."""

    def __init__(
        self,
        *,
        settings: "AISettings",
        provider: ProviderConfig,
        client: AIClient,
        prompt_builder: PromptBuilder | None = None,
        parser: ResponseParser | None = None,
    ) -> None:
        """Initialise the adapter.

        Args:
            settings: The AI configuration (provider, model, key, tuning).
            provider: The selected provider strategy.
            client: The HTTP client used to call the provider.
            prompt_builder: Builds sanitised prompts (defaulted).
            parser: Parses provider responses (defaulted).
        """

        self._settings = settings
        self._provider = provider
        self._client = client
        self._prompt_builder = prompt_builder or PromptBuilder()
        self._parser = parser or ResponseParser()

    def recommend(self, finding: Finding) -> Recommendation:
        """Return an AI-generated remediation recommendation for ``finding``.

        Args:
            finding: The finding to enrich.

        Returns:
            A domain ``Recommendation`` whose priority equals the finding's
            severity.

        Raises:
            AIError: If the provider is unreachable, unauthenticated, or returns
                an unusable response.
        """

        api_key = self._require_api_key()
        base_url = self._settings.base_url or self._provider.default_base_url
        model = self._settings.model

        system_prompt, user_prompt = self._prompt_builder.build(finding)
        url = self._provider.build_endpoint(base_url, model)
        headers = self._provider.build_headers(api_key)
        payload = self._provider.build_payload(
            system_prompt,
            user_prompt,
            model,
            self._settings.temperature,
            self._settings.max_tokens,
        )

        # Metadata only — never the key, never the prompt body.
        _logger.info("ai enrichment requested", provider=self._settings.provider, model=model)
        response = self._client.post_json(url, headers, payload)
        text = self._provider.extract_text(response)
        enrichment = self._parser.parse(text)
        _logger.info("ai enrichment received", confidence=enrichment.confidence)
        return self._to_recommendation(finding, enrichment)

    def _require_api_key(self) -> str:
        """Return the secret API key value, or raise if none is configured."""

        api_key = self._settings.api_key
        if api_key is None:
            raise AIAuthenticationError("no AI API key configured")
        # get_secret_value() is called only here, only to build headers; the
        # value is never logged or placed in any error context.
        return api_key.get_secret_value()

    def _to_recommendation(self, finding: Finding, enrichment: Enrichment) -> Recommendation:
        """Map an enrichment onto a domain Recommendation (severity preserved)."""

        sections: list[str] = []
        if enrichment.explanation:
            sections.append(f"Explanation: {enrichment.explanation}")
        if enrichment.business_impact:
            sections.append(f"Business impact: {enrichment.business_impact}")
        if enrichment.remediation:
            sections.append(f"Remediation: {enrichment.remediation}")
        if enrichment.references:
            sections.append("References:\n" + "\n".join(f"- {r}" for r in enrichment.references))
        sections.append(f"AI confidence: {enrichment.confidence:.2f}")

        title = enrichment.title or f"Remediation for {finding.title}"
        return Recommendation(
            title=title[:200],
            description="\n\n".join(sections),
            # Never trust the model's severity: use the finding's own severity.
            priority=finding.severity,
        )
