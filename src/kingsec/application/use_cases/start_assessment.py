"""Use case: start (run) an assessment.

Orchestrates a full run synchronously: transition to RUNNING (which enforces the
authorization gate in the domain), scan the target, enrich each finding with an
optional AI recommendation, record the findings, and complete.

Why synchronous here? The application layer models *what* happens. Real execution
will be asynchronous with progress milestones — but that scheduling/streaming is
an infrastructure concern, layered on top of this use case later, not baked into
the business logic.

AI enrichment is best-effort by design (bring-your-own-key, optional): a provider
failure must never fail an authorized scan, so enrichment errors are swallowed.
Observability for those failures is added at the adapter, which can log them.
"""

from __future__ import annotations

from kingsec.domain import Finding

from .._support import to_assessment_id
from ..dto import StartAssessmentRequest, StartAssessmentResponse
from ..ports import AIPort, AssessmentRepository, ScannerPort


class StartAssessment:
    """Run an authorized assessment to completion."""

    def __init__(
        self,
        assessments: AssessmentRepository,
        scanner: ScannerPort,
        ai: AIPort | None = None,
    ) -> None:
        self._assessments = assessments
        self._scanner = scanner
        self._ai = ai  # optional: AI enrichment is not required to run a scan

    def execute(self, request: StartAssessmentRequest) -> StartAssessmentResponse:
        assessment = self._assessments.get(to_assessment_id(request.assessment_id))

        # The authorization gate lives in the domain: this raises
        # IllegalStateTransition if the assessment was never authorized. We let
        # that domain error propagate — it is a precise, meaningful signal.
        assessment.start()

        for finding in self._scanner.scan(assessment.target):
            self._enrich(finding)
            assessment.record_finding(finding)

        assessment.complete()
        self._assessments.save(assessment)

        highest = assessment.highest_severity
        return StartAssessmentResponse(
            assessment_id=str(assessment.id),
            status=assessment.status.value,
            findings_count=len(assessment.findings),
            highest_severity=highest.label if highest is not None else None,
        )

    def _enrich(self, finding: Finding) -> None:
        """Attach an AI recommendation if an AI port is configured (best-effort)."""

        if self._ai is None:
            return
        try:
            recommendation = self._ai.recommend(finding)
            finding.add_recommendation(recommendation)
        except Exception:  # noqa: BLE001 - enrichment is optional, never fatal
            # Intentionally swallowed: an AI outage must not fail an authorized
            # scan. The adapter is responsible for logging the underlying error.
            return
