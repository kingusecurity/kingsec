from __future__ import annotations

from datetime import UTC, datetime

from kingsec.application.ports.job_service import JobServicePort
from kingsec.application.ports.notification_service import NotificationServicePort
from kingsec.application.ports.outbound import PipelineOrchestratorPort
from kingsec.application.ports.outbound.agent_dispatcher import AgentDispatcherPort
from kingsec.application.ports.outbound.audit_publisher import AuditPublisher
from kingsec.application.ports.queue_service import QueueServicePort
from kingsec.application.ports.report_service import ReportServicePort
from kingsec.domain.agent import AgentId
from kingsec.domain.notification import (
    Notification,
    NotificationChannel,
    NotificationId,
    NotificationPriority,
    NotificationStatus,
)
from kingsec.domain.pipeline import (
    PIPELINE_ORDER,
    PipelineExecution,
    PipelineResult,
    PipelineStage,
    PipelineState,
)


class PipelineOrchestrator(PipelineOrchestratorPort):
    """Coordinates pipeline state transitions by invoking service ports only.
    Never calls scanners directly.
    """

    def __init__(
        self,
        job_service: JobServicePort,
        queue_service: QueueServicePort,
        agent_dispatcher: AgentDispatcherPort,
        report_service: ReportServicePort,
        notification_service: NotificationServicePort,
        audit: AuditPublisher,
    ) -> None:
        self._job_service = job_service
        self._queue_service = queue_service
        self._agent_dispatcher = agent_dispatcher
        self._report_service = report_service
        self._notification_service = notification_service
        self._audit = audit

    def advance(self, execution: PipelineExecution) -> PipelineExecution:
        current = execution.state
        current_idx = next((i for i, s in enumerate(PIPELINE_ORDER) if s == current), -1)
        if current_idx < 0 or current_idx >= len(PIPELINE_ORDER) - 1:
            return execution
        next_state = PIPELINE_ORDER[current_idx + 1]
        now = datetime.now(UTC).isoformat()
        stages = list(execution.stages)
        current_stage = execution.stages[current_idx] if current_idx < len(stages) else None
        next_stage = execution.stages[current_idx + 1] if current_idx + 1 < len(stages) else None

        if current_stage:
            stages[current_idx] = PipelineStage(
                name=current_stage.name,
                status="completed",
                started_at=current_stage.started_at or now,
                completed_at=now,
                error_message=current_stage.error_message,
            )
        if next_stage:
            stages[current_idx + 1] = PipelineStage(
                name=next_stage.name,
                status="running",
                started_at=now,
                completed_at="",
                error_message="",
            )

        result = execution.result
        try:
            if next_state == PipelineState.ASSIGNED:
                entry = self._queue_service.enqueue(
                    payload=execution.target,
                    target=execution.target,
                    priority=execution.priority,
                    scanner_ids=list(execution.scanner_ids),
                    owner_user_id=execution.owner_user_id,
                )
                result = PipelineResult(
                    queue_entry_id=entry.entry_id,
                    job_id=result.job_id,
                    agent_id=result.agent_id,
                    report_id=result.report_id,
                    notification_ids=result.notification_ids,
                    findings_count=result.findings_count,
                    summary=result.summary,
                    error_message=result.error_message,
                    started_at=result.started_at or now,
                    completed_at=result.completed_at,
                )

            elif next_state == PipelineState.RUNNING:
                job = self._job_service.submit_scan(target=execution.target)
                result = PipelineResult(
                    queue_entry_id=result.queue_entry_id,
                    job_id=job.id if hasattr(job, 'id') else str(job),
                    agent_id=result.agent_id,
                    report_id=result.report_id,
                    notification_ids=result.notification_ids,
                    findings_count=result.findings_count,
                    summary=result.summary,
                    error_message=result.error_message,
                    started_at=result.started_at or now,
                    completed_at=result.completed_at,
                )
                if execution.result.agent_id:
                    self._agent_dispatcher.assign_job(AgentId(execution.result.agent_id), "")

            elif next_state == PipelineState.COLLECTING_RESULTS:
                try:
                    job_result = self._job_service.get_job_result(result.job_id)
                    findings = getattr(job_result, 'findings', []) or []
                    fc = len(findings)
                    result = PipelineResult(
                        queue_entry_id=result.queue_entry_id,
                        job_id=result.job_id,
                        agent_id=result.agent_id,
                        report_id=result.report_id,
                        notification_ids=result.notification_ids,
                        findings_count=fc,
                        summary=result.summary,
                        error_message=result.error_message,
                        started_at=result.started_at,
                        completed_at=now,
                    )
                except Exception as exc:
                    return self._build_failed(execution, stages, result, now, str(exc))

            elif next_state == PipelineState.GENERATING_REPORT:
                try:
                    report = self._report_service.generate_report(scan_id=result.job_id)
                    result = PipelineResult(
                        queue_entry_id=result.queue_entry_id,
                        job_id=result.job_id,
                        agent_id=result.agent_id,
                        report_id=getattr(report, 'report_id', ""),
                        notification_ids=result.notification_ids,
                        findings_count=result.findings_count,
                        summary=getattr(report, 'summary', ""),
                        error_message=result.error_message,
                        started_at=result.started_at,
                        completed_at=now,
                    )
                except Exception as exc:
                    return self._build_failed(execution, stages, result, now, str(exc))

            elif next_state == PipelineState.SENDING_NOTIFICATION:
                try:
                    notif = Notification(
                        id=NotificationId(value=f"notif-{execution.pipeline_id.value}"),
                        user_id=execution.owner_user_id,
                        title=f"Pipeline {execution.pipeline_id.value} completed",
                        message=f"Scan of {execution.target} completed with {result.findings_count} findings",
                        channel=NotificationChannel.IN_APP,
                        status=NotificationStatus.PENDING,
                        priority=NotificationPriority.MEDIUM,
                        event_type="pipeline.completed",
                        template_vars={},
                        retry_count=0,
                        max_retries=3,
                        created_at=now,
                        updated_at=now,
                    )
                    sent = self._notification_service.send(notif)
                    notif_ids = (sent.id.value,) if sent else ()
                    result = PipelineResult(
                        queue_entry_id=result.queue_entry_id,
                        job_id=result.job_id,
                        agent_id=result.agent_id,
                        report_id=result.report_id,
                        notification_ids=tuple(set(result.notification_ids + notif_ids)),
                        findings_count=result.findings_count,
                        summary=result.summary,
                        error_message=result.error_message,
                        started_at=result.started_at,
                        completed_at=now,
                    )
                except Exception as exc:
                    return self._build_failed(execution, stages, result, now, str(exc))

            elif next_state == PipelineState.COMPLETED:
                result = PipelineResult(
                    queue_entry_id=result.queue_entry_id,
                    job_id=result.job_id,
                    agent_id=result.agent_id,
                    report_id=result.report_id,
                    notification_ids=result.notification_ids,
                    findings_count=result.findings_count,
                    summary=result.summary,
                    error_message="",
                    started_at=result.started_at,
                    completed_at=now,
                )

        except Exception as exc:
            return self._build_failed(execution, stages, result, now, str(exc))

        return PipelineExecution(
            pipeline_id=execution.pipeline_id,
            target=execution.target,
            state=next_state,
            stages=tuple(stages),
            result=result,
            owner_user_id=execution.owner_user_id,
            scanner_ids=execution.scanner_ids,
            priority=execution.priority,
            created_at=execution.created_at,
            updated_at=now,
        )

    def cancel(self, execution: PipelineExecution) -> PipelineExecution:
        now = datetime.now(UTC).isoformat()
        stages = list(execution.stages)
        current_idx = next((i for i, s in enumerate(PIPELINE_ORDER) if s == execution.state), -1)
        if 0 <= current_idx < len(stages):
            s = stages[current_idx]
            stages[current_idx] = PipelineStage(
                name=s.name, status="failed", started_at=s.started_at,
                completed_at=now, error_message="Cancelled",
            )
        result = PipelineResult(
            queue_entry_id=execution.result.queue_entry_id,
            job_id=execution.result.job_id,
            agent_id=execution.result.agent_id,
            report_id=execution.result.report_id,
            notification_ids=execution.result.notification_ids,
            findings_count=execution.result.findings_count,
            summary=execution.result.summary,
            error_message="Pipeline cancelled",
            started_at=execution.result.started_at,
            completed_at=now,
        )
        return PipelineExecution(
            pipeline_id=execution.pipeline_id,
            target=execution.target,
            state=PipelineState.CANCELLED,
            stages=tuple(stages),
            result=result,
            owner_user_id=execution.owner_user_id,
            scanner_ids=execution.scanner_ids,
            priority=execution.priority,
            created_at=execution.created_at,
            updated_at=now,
        )

    def retry(self, execution: PipelineExecution) -> PipelineExecution:
        now = datetime.now(UTC).isoformat()
        stages = list(execution.stages)
        current_idx = next((i for i, s in enumerate(PIPELINE_ORDER) if s == execution.state), -1)
        if 0 <= current_idx < len(stages):
            s = stages[current_idx]
            stages[current_idx] = PipelineStage(
                name=s.name, status="running", started_at=s.started_at or now,
                completed_at="", error_message="",
            )
        return PipelineExecution(
            pipeline_id=execution.pipeline_id,
            target=execution.target,
            state=execution.state,
            stages=tuple(stages),
            result=PipelineResult(
                queue_entry_id=execution.result.queue_entry_id,
                job_id=execution.result.job_id,
                agent_id=execution.result.agent_id,
                report_id=execution.result.report_id,
                notification_ids=execution.result.notification_ids,
                findings_count=execution.result.findings_count,
                summary=execution.result.summary,
                error_message="",
                started_at=execution.result.started_at,
                completed_at="",
            ),
            owner_user_id=execution.owner_user_id,
            scanner_ids=execution.scanner_ids,
            priority=execution.priority,
            created_at=execution.created_at,
            updated_at=now,
        )

    def pause(self, execution: PipelineExecution) -> PipelineExecution:
        return execution

    def resume(self, execution: PipelineExecution) -> PipelineExecution:
        return execution

    def _build_failed(self, execution: PipelineExecution, stages: list,
                      result: PipelineResult, now: str, error: str) -> PipelineExecution:
        current_idx = next((i for i, s in enumerate(PIPELINE_ORDER) if s == execution.state), -1)
        if 0 <= current_idx < len(stages):
            s = stages[current_idx]
            stages[current_idx] = PipelineStage(
                name=s.name, status="failed", started_at=s.started_at or now,
                completed_at=now, error_message=error,
            )
        return PipelineExecution(
            pipeline_id=execution.pipeline_id,
            target=execution.target,
            state=PipelineState.FAILED,
            stages=tuple(stages),
            result=PipelineResult(
                queue_entry_id=result.queue_entry_id,
                job_id=result.job_id,
                agent_id=result.agent_id,
                report_id=result.report_id,
                notification_ids=result.notification_ids,
                findings_count=result.findings_count,
                summary=result.summary,
                error_message=error,
                started_at=result.started_at,
                completed_at=now,
            ),
            owner_user_id=execution.owner_user_id,
            scanner_ids=execution.scanner_ids,
            priority=execution.priority,
            created_at=execution.created_at,
            updated_at=now,
        )
