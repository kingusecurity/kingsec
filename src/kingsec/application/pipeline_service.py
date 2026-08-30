from __future__ import annotations

from kingsec.application.ports.outbound import PipelineOrchestratorPort, PipelineRepositoryPort
from kingsec.application.ports.outbound.audit_publisher import AuditPublisher
from kingsec.application.ports.pipeline_service import PipelineServicePort
from kingsec.application.use_cases.pipeline import (
    AdvancePipeline,
    CancelPipeline,
    GetPipeline,
    ListPipelines,
    PausePipeline,
    ResumePipeline,
    RetryPipeline,
    StartPipeline,
)
from kingsec.domain.pipeline import PipelineExecution


class PipelineService(PipelineServicePort):
    def __init__(
        self, repo: PipelineRepositoryPort, orchestrator: PipelineOrchestratorPort, audit: AuditPublisher
    ) -> None:
        self._start_uc = StartPipeline(repo, orchestrator, audit)
        self._get_uc = GetPipeline(repo)
        self._list_uc = ListPipelines(repo)
        self._cancel_uc = CancelPipeline(repo, orchestrator, audit)
        self._retry_uc = RetryPipeline(repo, orchestrator, audit)
        self._resume_uc = ResumePipeline(repo, orchestrator, audit)
        self._pause_uc = PausePipeline(repo, orchestrator, audit)
        self._advance_uc = AdvancePipeline(repo, orchestrator, audit)

    def start_pipeline(
        self, target: str, owner_user_id: str = "", scanner_ids: list[str] | None = None, priority: str = "normal"
    ) -> PipelineExecution:
        return self._start_uc.execute(target, owner_user_id, scanner_ids, priority)

    def get_pipeline(
        self, pipeline_id: str, requesting_user_id: str = "", is_admin: bool = False
    ) -> PipelineExecution:
        return self._get_uc.execute(pipeline_id, requesting_user_id, is_admin)

    def list_pipelines(self, requesting_user_id: str = "", is_admin: bool = False) -> list[PipelineExecution]:
        return self._list_uc.execute(requesting_user_id, is_admin)

    def cancel_pipeline(self, pipeline_id: str) -> PipelineExecution:
        return self._cancel_uc.execute(pipeline_id)

    def retry_pipeline(self, pipeline_id: str) -> PipelineExecution:
        return self._retry_uc.execute(pipeline_id)

    def resume_pipeline(self, pipeline_id: str) -> PipelineExecution:
        return self._resume_uc.execute(pipeline_id)

    def pause_pipeline(self, pipeline_id: str) -> PipelineExecution:
        return self._pause_uc.execute(pipeline_id)

    def advance_pipeline(self, pipeline_id: str) -> PipelineExecution:
        return self._advance_uc.execute(pipeline_id)
