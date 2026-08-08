"""AI integration tests: real HTTP server + full enriched, persisted slice."""

from __future__ import annotations

from collections.abc import Sequence
from pathlib import Path

import pytest
from pydantic import SecretStr

from kingsec.application import (
    CreateAssessment,
    CreateAssessmentRequest,
    GetAssessment,
    GetAssessmentRequest,
    ScannerPort,
    StartAssessment,
    StartAssessmentRequest,
)
from kingsec.domain import Evidence, Finding, Severity, Target
from kingsec.infrastructure.ai import (
    AIClient,
    AIProviderAdapter,
    resolve_provider,
)
from kingsec.infrastructure.ai.errors import AIError
from kingsec.infrastructure.config.models import AISettings
from kingsec.infrastructure.persistence import (
    LegacyAssessmentRepository,
    create_database_engine,
    create_schema,
    create_session_factory,
)


def _adapter(base_url: str) -> AIProviderAdapter:
    settings = AISettings(provider="openai", api_key=SecretStr("test-key"), base_url=base_url, retry_count=1)
    client = AIClient(
        timeout=5,
        retry_count=settings.retry_count,
        retry_delay=0,
        verify_ssl=settings.verify_ssl,
    )
    return AIProviderAdapter(settings=settings, provider=resolve_provider("openai"), client=client)


def _finding() -> Finding:
    f = Finding.create("SQLi", "injectable", Severity.CRITICAL)
    f.add_evidence(Evidence.create("m", "matched http://10.0.0.5"))
    return f


class _StubScanner(ScannerPort):
    def scan(self, target: Target) -> Sequence[Finding]:
        return [Finding.create("SQLi", "injectable", Severity.CRITICAL)]

    def compatible_scanners(self, target: Target) -> dict[str, str]:
        return {"stub": "Stub Scanner"}


class TestRealServer:
    def test_happy_path_enriches(self, ai_server) -> None:
        base_url, _state = ai_server
        rec = _adapter(base_url).recommend(_finding())
        assert rec.priority is Severity.CRITICAL
        assert "parameterised queries" in rec.description.lower()

    def test_server_error_becomes_ai_error(self, ai_server) -> None:
        base_url, state = ai_server
        state.mode = "error"
        with pytest.raises(AIError):
            _adapter(base_url).recommend(_finding())

    def test_malformed_response_becomes_ai_error(self, ai_server) -> None:
        base_url, state = ai_server
        state.mode = "malformed"
        with pytest.raises(AIError):
            _adapter(base_url).recommend(_finding())


class TestFullSlice:
    def _repo(self, tmp_path: Path) -> LegacyAssessmentRepository:
        engine = create_database_engine(url=f"sqlite:///{tmp_path / 'k.db'}")
        create_schema(engine)
        self._engine = engine
        return LegacyAssessmentRepository(create_session_factory(engine))

    def test_scan_enrich_and_persist(self, tmp_path: Path, ai_server) -> None:
        base_url, _state = ai_server
        assessments = self._repo(tmp_path)
        try:
            created = CreateAssessment(assessments).execute(
                CreateAssessmentRequest("10.0.0.5", "ip_address", "tester", "10.0.0.5")
            )
            StartAssessment(assessments, _StubScanner(), _adapter(base_url)).execute(
                StartAssessmentRequest(created.assessment_id)
            )

            view = GetAssessment(assessments).execute(GetAssessmentRequest(created.assessment_id, is_admin=True))
            # The finding was enriched with an AI recommendation and persisted.
            assert view.findings[0].recommendation_count == 1
        finally:
            self._engine.dispose()

    def test_ai_outage_does_not_fail_the_scan(self, tmp_path: Path, ai_server) -> None:
        base_url, state = ai_server
        state.mode = "error"  # AI returns 500 every time
        assessments = self._repo(tmp_path)
        try:
            created = CreateAssessment(assessments).execute(
                CreateAssessmentRequest("10.0.0.5", "ip_address", "tester", "10.0.0.5")
            )
            # Fail-safe: the scan still completes despite the AI being down.
            started = StartAssessment(assessments, _StubScanner(), _adapter(base_url)).execute(
                StartAssessmentRequest(created.assessment_id)
            )

            assert started.status == "completed"
            assert started.findings_count == 1
            view = GetAssessment(assessments).execute(GetAssessmentRequest(created.assessment_id, is_admin=True))
            # Finding recorded unchanged — just without an AI recommendation.
            assert view.findings[0].recommendation_count == 0
        finally:
            self._engine.dispose()
