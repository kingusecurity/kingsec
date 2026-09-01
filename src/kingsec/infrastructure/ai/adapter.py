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
from kingsec.application.ports import UnsafeURLError, URLValidationPort
from kingsec.domain import Finding, Recommendation
from kingsec.infrastructure.logging import get_logger

from .client import AIClient
from .config_resolver import AIConfigResolver, ResolvedAIConfig
from .errors import AIAuthenticationError, AIUnsafeURLError
from .parser import Enrichment, ResponseParser
from .prompt import PromptBuilder

if TYPE_CHECKING:  # typing only; no runtime import of config internals
    from kingsec.infrastructure.config.models import AISettings

_logger = get_logger("kingsec.infrastructure.ai")


class AIProviderAdapter(AIPort):
    """Enriches a finding with AI-generated remediation guidance.

    Provider/API key/model/base_url are resolved fresh on every call via
    ``config_resolver`` (DB-saved settings override env-var ``AISettings``
    when present) - a save from the Settings UI takes effect on the very
    next call, no restart needed. Only the tuning knobs that stay env-only
    by design (temperature, max_tokens) are read from the fixed ``settings``
    captured at composition time; they were never meant to be user-editable.
    """

    def __init__(
        self,
        *,
        settings: AISettings,
        config_resolver: AIConfigResolver,
        client: AIClient,
        url_validator: URLValidationPort,
        prompt_builder: PromptBuilder | None = None,
        parser: ResponseParser | None = None,
    ) -> None:
        """Initialise the adapter.

        Args:
            settings: The env-var AI configuration - only its tuning knobs
                (temperature, max_tokens) are used directly; provider/key/
                model/base_url come from config_resolver instead.
            config_resolver: Resolves the effective provider/key/model/
                base_url fresh on every call.
            client: The HTTP client used to call the provider.
            url_validator: Validates a database-sourced base_url (i.e. one
                that originated from a Settings-UI request body) before it
                is used to build an outbound request. Environment-sourced
                base_url is deployment configuration, not request input, and
                is never passed to this validator - see _validate_base_url().
            prompt_builder: Builds sanitised prompts (defaulted).
            parser: Parses provider responses (defaulted).
        """
        self._settings = settings
        self._config_resolver = config_resolver
        self._client = client
        self._url_validator = url_validator
        self._prompt_builder = prompt_builder or PromptBuilder()
        self._parser = parser or ResponseParser()

    def _validate_base_url(self, resolved: ResolvedAIConfig) -> None:
        """Validate a request-supplied base_url before it is used to build
        an outbound request.

        Only database-sourced base_url is validated: it originated from a
        PUT /api/v1/settings/ai-provider request body, i.e. request input.
        Environment-sourced base_url (KINGSEC_AI__BASE_URL) is operator
        configuration set at deploy time - the same trust category as
        diagnostics.py's hardcoded probe - and is intentionally never
        validated here, so a local model server remains configurable via
        the environment with no opt-in flag required.
        """
        if resolved.source != "database" or not resolved.base_url:
            return
        try:
            self._url_validator.validate(resolved.base_url)
        except UnsafeURLError as exc:
            raise AIUnsafeURLError(f"AI base_url blocked by SSRF protection: {exc}") from exc

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
        enrichment = self._enrich(finding)
        return self._to_recommendation(finding, enrichment)

    def explain_business_risk(self, finding: Finding) -> str:
        """Return a plain-language, business-risk explanation of ``finding``.

        Args:
            finding: The finding to explain.

        Returns:
            Prose combining the AI's plain-language explanation and business-
            impact framing (whichever parts the response actually included).

        Raises:
            AIError: If the provider is unreachable, unauthenticated, or returns
                an unusable response.
        """
        enrichment = self._enrich(finding)
        parts = [p for p in (enrichment.explanation, enrichment.business_impact) if p]
        return "\n\n".join(parts) if parts else f"The AI provider returned no explanation for {finding.title!r}."

    def _enrich(self, finding: Finding) -> Enrichment:
        """Call the provider and parse its response for ``finding`` (shared by
        ``recommend()`` and ``explain_business_risk()``)."""
        resolved = self._config_resolver.resolve()
        if resolved.api_key is None:
            raise AIAuthenticationError("no AI API key configured")
        self._validate_base_url(resolved)
        base_url = resolved.base_url or resolved.provider.default_base_url
        model = resolved.model

        system_prompt, user_prompt = self._prompt_builder.build(finding)
        url = resolved.provider.build_endpoint(base_url, model)
        headers = resolved.provider.build_headers(resolved.api_key)
        payload = resolved.provider.build_payload(
            system_prompt,
            user_prompt,
            model,
            self._settings.temperature,
            self._settings.max_tokens,
        )

        # Metadata only — never the key, never the prompt body.
        _logger.info("ai enrichment requested", provider=resolved.provider.name, model=model, source=resolved.source)
        # KSEC-85-01: the client's own resolve-and-pin step runs either way
        # (closing the TOCTOU), but its private/reserved-range *policy* must
        # track _validate_base_url()'s own trust decision exactly - an
        # environment-sourced base_url is deployment configuration that was
        # never subject to that policy (see _validate_base_url()'s
        # docstring), so it is passed as allow_private=True here too, not
        # left to whatever policy this AIClient instance happens to be
        # constructed with.
        response = self._client.post_json(
            url, headers, payload, allow_private=True if resolved.source != "database" else None
        )
        text = resolved.provider.extract_text(response)
        enrichment = self._parser.parse(text)
        _logger.info("ai enrichment received", confidence=enrichment.confidence)
        return enrichment

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
