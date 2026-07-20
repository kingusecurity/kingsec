from __future__ import annotations

from datetime import UTC, datetime

from kingsec.application.ports.outbound import PipelineOrchestratorPort, PipelineRepositoryPort
from kingsec.application.ports.outbound.audit_publisher import AuditPublisher
from kingsec.domain.audit import AuditAction, AuditEntry
from kingsec.domain.pipeline import (
    PIPELINE_ORDER,
    PipelineExecution,
    PipelineId,
    PipelineResult,
    PipelineStage,
    PipelineState,
)


class StartPipeline:
    def __init__(self, repo: PipelineRepositoryPort, orchestrator: PipelineOrchestratorPort,
                 audit: AuditPublisher) -> None:
        self._repo = repo
        self._orchestrator = orchestrator
        self._audit = audit
        self._counter = 0

    def execute(self, target: str, owner_user_id: str = "",
                scanner_ids: list[str] | None = None,
                priority: str = "normal") -> PipelineExecution:
        self._counter += 1
        pipeline_id = PipelineId(value=f"pl-{self._counter}")
        stages = tuple(
            PipelineStage(name=s.value, status="completed" if s == PipelineState.QUEUED else "pending",
                          started_at=datetime.now(UTC).isoformat() if s == PipelineState.QUEUED else "")
            for s in PIPELINE_ORDER
        )
        execution = PipelineExecution(
            pipeline_id=pipeline_id,
            target=target,
            state=PipelineState.QUEUED,
            stages=stages,
            owner_user_id=owner_user_id,
            scanner_ids=tuple(scanner_ids or []),
            priority=priority,
        )
        self._repo.save(execution)
        self._audit.record(AuditEntry(
            action=AuditAction.PIPELINE_STARTED,
            resource_type="pipeline",
            resource_id=pipeline_id.value,
            success=True,
            username=owner_user_id,
        ))
        return execution


class GetPipeline:
    def __init__(self, repo: PipelineRepositoryPort) -> None:
        self._repo = repo

    def execute(self, pipeline_id: str) -> PipelineExecution:
        execution = self._repo.find_by_id(pipeline_id)
        if not execution:
            from kingsec.application.errors import PipelineNotFoundError
            raise PipelineNotFoundError(f"Pipeline '{pipeline_id}' not found")
        return execution


class ListPipelines:
    def __init__(self, repo: PipelineRepositoryPort) -> None:
        self._repo = repo

    def execute(self) -> list[PipelineExecution]:
        return self._repo.find_all()


class CancelPipeline:
    def __init__(self, repo: PipelineRepositoryPort, orchestrator: PipelineOrchestratorPort,
                 audit: AuditPublisher) -> None:
        self._repo = repo
        self._orchestrator = orchestrator
        self._audit = audit

    def execute(self, pipeline_id: str) -> PipelineExecution:
        execution = self._repo.find_by_id(pipeline_id)
        if not execution:
            from kingsec.application.errors import PipelineNotFoundError
            raise PipelineNotFoundError(f"Pipeline '{pipeline_id}' not found")
        if execution.state in (PipelineState.COMPLETED, PipelineState.CANCELLED):
            from kingsec.application.errors import PipelineStateConflictError
            raise PipelineStateConflictError(f"Cannot cancel pipeline in state '{execution.state.value}'")
        result = self._orchestrator.cancel(execution)
        self._repo.save(result)
        self._audit.record(AuditEntry(
            action=AuditAction.PIPELINE_CANCELLED,
            resource_type="pipeline",
            resource_id=pipeline_id,
            success=True,
        ))
        return result


class RetryPipeline:
    def __init__(self, repo: PipelineRepositoryPort, orchestrator: PipelineOrchestratorPort,
                 audit: AuditPublisher) -> None:
        self._repo = repo
        self._orchestrator = orchestrator
        self._audit = audit

    def execute(self, pipeline_id: str) -> PipelineExecution:
        execution = self._repo.find_by_id(pipeline_id)
        if not execution:
            from kingsec.application.errors import PipelineNotFoundError
            raise PipelineNotFoundError(f"Pipeline '{pipeline_id}' not found")
        if execution.state != PipelineState.FAILED:
            from kingsec.application.errors import PipelineStateConflictError
            raise PipelineStateConflictError(f"Cannot retry pipeline in state '{execution.state.value}'")
        result = self._orchestrator.retry(execution)
        self._repo.save(result)
        self._audit.record(AuditEntry(
            action=AuditAction.PIPELINE_RETRIED,
            resource_type="pipeline",
            resource_id=pipeline_id,
            success=True,
        ))
        return result


class ResumePipeline:
    def __init__(self, repo: PipelineRepositoryPort, orchestrator: PipelineOrchestratorPort,
                 audit: AuditPublisher) -> None:
        self._repo = repo
        self._orchestrator = orchestrator
        self._audit = audit

    def execute(self, pipeline_id: str) -> PipelineExecution:
        execution = self._repo.find_by_id(pipeline_id)
        if not execution:
            from kingsec.application.errors import PipelineNotFoundError
            raise PipelineNotFoundError(f"Pipeline '{pipeline_id}' not found")
        result = self._orchestrator.resume(execution)
        self._repo.save(result)
        self._audit.record(AuditEntry(
            action=AuditAction.PIPELINE_RESUMED,
            resource_type="pipeline",
            resource_id=pipeline_id,
            success=True,
        ))
        return result


class PausePipeline:
    def __init__(self, repo: PipelineRepositoryPort, orchestrator: PipelineOrchestratorPort,
                 audit: AuditPublisher) -> None:
        self._repo = repo
        self._orchestrator = orchestrator
        self._audit = audit

    def execute(self, pipeline_id: str) -> PipelineExecution:
        execution = self._repo.find_by_id(pipeline_id)
        if not execution:
            from kingsec.application.errors import PipelineNotFoundError
            raise PipelineNotFoundError(f"Pipeline '{pipeline_id}' not found")
        result = self._orchestrator.pause(execution)
        self._repo.save(result)
        self._audit.record(AuditEntry(
            action=AuditAction.PIPELINE_PAUSED,
            resource_type="pipeline",
            resource_id=pipeline_id,
            success=True,
        ))
        return result


class AdvancePipeline:
    def __init__(self, repo: PipelineRepositoryPort, orchestrator: PipelineOrchestratorPort,
                 audit: AuditPublisher) -> None:
        self._repo = repo
        self._orchestrator = orchestrator
        self._audit = audit

    def execute(self, pipeline_id: str) -> PipelineExecution:
        execution = self._repo.find_by_id(pipeline_id)
        if not execution:
            from kingsec.application.errors import PipelineNotFoundError
            raise PipelineNotFoundError(f"Pipeline '{pipeline_id}' not found")
        result = self._orchestrator.advance(execution)
        self._repo.save(result)
        stage_name = result.state.value
        self._audit.record(AuditEntry(
            action=AuditAction.PIPELINE_ADVANCED,
            resource_type="pipeline",
            resource_id=pipeline_id,
            success=True,
            detail=f"Advanced to stage '{stage_name}'",
        ))
        return result


class PipelineDto:
    def __init__(self, execution: PipelineExecution) -> None:
        self.pipeline_id = execution.pipeline_id.value
        self.target = execution.target
        self.state = execution.state.value
        self.stages = [
            {
                "name": s.name,
                "status": s.status,
                "started_at": s.started_at,
                "completed_at": s.completed_at,
                "error_message": s.error_message,
            }
            for s in execution.stages
        ]
        self.job_id = execution.result.job_id
        self.queue_entry_id = execution.result.queue_entry_id
        self.agent_id = execution.result.agent_id
        self.report_id = execution.result.report_id
        self.notification_ids = list(execution.result.notification_ids)
        self.findings_count = execution.result.findings_count
        self.summary = execution.result.summary
        self.error_message = execution.result.error_message
        self.owner_user_id = execution.owner_user_id
        self.scanner_ids = list(execution.scanner_ids)
        self.priority = execution.priority
        self.created_at = execution.created_at
        self.updated_at = execution.updated_at
