from __future__ import annotations

from unittest.mock import MagicMock

import pytest

from kingsec.application.ports.job_service import JobServicePort
from kingsec.application.ports.notification_service import NotificationServicePort
from kingsec.application.ports.outbound.agent_dispatcher import AgentDispatcherPort
from kingsec.application.ports.outbound.audit_publisher import AuditPublisher
from kingsec.application.ports.queue_service import QueueServicePort
from kingsec.application.ports.report_service import ReportServicePort
from kingsec.domain.pipeline import (
    PIPELINE_ORDER,
    PipelineExecution,
    PipelineId,
    PipelineResult,
    PipelineStage,
    PipelineState,
)
from kingsec.infrastructure.pipeline.orchestrator import PipelineOrchestrator


@pytest.fixture
def job_service() -> MagicMock:
    return MagicMock(spec=JobServicePort)


@pytest.fixture
def queue_service() -> MagicMock:
    svc = MagicMock(spec=QueueServicePort)
    entry = MagicMock()
    entry.entry_id = "q-1"
    svc.enqueue.return_value = entry
    return svc


@pytest.fixture
def agent_dispatcher() -> MagicMock:
    return MagicMock(spec=AgentDispatcherPort)


@pytest.fixture
def report_service() -> MagicMock:
    svc = MagicMock(spec=ReportServicePort)
    report = MagicMock()
    report.report_id = "report-1"
    report.summary = "Scan complete"
    svc.generate_report.return_value = report
    return svc


@pytest.fixture
def notification_service() -> MagicMock:
    svc = MagicMock(spec=NotificationServicePort)
    notif = MagicMock()
    notif.id.value = "notif-1"
    svc.send.return_value = notif
    return svc


@pytest.fixture
def audit() -> MagicMock:
    return MagicMock(spec=AuditPublisher)


@pytest.fixture
def orchestrator(
    job_service, queue_service, agent_dispatcher, report_service, notification_service, audit
) -> PipelineOrchestrator:
    return PipelineOrchestrator(
        job_service=job_service,
        queue_service=queue_service,
        agent_dispatcher=agent_dispatcher,
        report_service=report_service,
        notification_service=notification_service,
        audit=audit,
    )


def _make_execution(state: PipelineState) -> PipelineExecution:
    try:
        state_idx = PIPELINE_ORDER.index(state)
    except ValueError:
        state_idx = len(PIPELINE_ORDER)
    stages = tuple(
        PipelineStage(
            name=s.value,
            status="completed" if PIPELINE_ORDER.index(s) < state_idx else "running" if s == state else "pending",
            started_at="2025-01-01T00:00:00",
            completed_at="2025-01-01T00:00:00" if PIPELINE_ORDER.index(s) < state_idx else "",
        )
        for s in PIPELINE_ORDER
    )
    return PipelineExecution(
        pipeline_id=PipelineId(value="pl-1"),
        target="10.0.0.1",
        state=state,
        stages=stages,
        owner_user_id="u1",
        scanner_ids=("nuclei",),
        priority="normal",
    )


class TestAdvance:
    def test_advance_from_queued_to_assigned(self, orchestrator, queue_service) -> None:
        exec_ = _make_execution(PipelineState.QUEUED)
        result = orchestrator.advance(exec_)
        assert result.state == PipelineState.ASSIGNED
        assert result.result.queue_entry_id == "q-1"
        queue_service.enqueue.assert_called_once()

    def test_advance_from_assigned_to_running(self, orchestrator, job_service) -> None:
        job = MagicMock()
        job.id = "job-1"
        job_service.submit_scan.return_value = job
        exec_ = _make_execution(PipelineState.ASSIGNED)
        exec_ = PipelineExecution(
            pipeline_id=exec_.pipeline_id,
            target=exec_.target,
            state=exec_.state,
            stages=exec_.stages,
            result=PipelineResult(queue_entry_id="q-1"),
            owner_user_id=exec_.owner_user_id,
            scanner_ids=exec_.scanner_ids,
            priority=exec_.priority,
        )
        result = orchestrator.advance(exec_)
        assert result.state == PipelineState.RUNNING
        assert result.result.job_id == "job-1"

    def test_advance_to_collecting_results(self, orchestrator, job_service) -> None:
        job_result = MagicMock()
        job_result.findings = [MagicMock(), MagicMock()]
        job_service.get_job_result.return_value = job_result
        exec_ = _make_execution(PipelineState.RUNNING)
        exec_ = PipelineExecution(
            pipeline_id=exec_.pipeline_id,
            target=exec_.target,
            state=exec_.state,
            stages=exec_.stages,
            result=PipelineResult(job_id="job-1", queue_entry_id="q-1"),
            owner_user_id=exec_.owner_user_id,
            scanner_ids=exec_.scanner_ids,
            priority=exec_.priority,
        )
        result = orchestrator.advance(exec_)
        assert result.state == PipelineState.COLLECTING_RESULTS
        assert result.result.findings_count >= 2

    def test_advance_to_generating_report(self, orchestrator, report_service) -> None:
        exec_ = _make_execution(PipelineState.COLLECTING_RESULTS)
        exec_ = PipelineExecution(
            pipeline_id=exec_.pipeline_id,
            target=exec_.target,
            state=exec_.state,
            stages=exec_.stages,
            result=PipelineResult(job_id="job-1", queue_entry_id="q-1", findings_count=3),
            owner_user_id=exec_.owner_user_id,
            scanner_ids=exec_.scanner_ids,
            priority=exec_.priority,
        )
        result = orchestrator.advance(exec_)
        assert result.state == PipelineState.GENERATING_REPORT
        assert result.result.report_id == "report-1"

    def test_advance_to_sending_notification(self, orchestrator, notification_service) -> None:
        exec_ = _make_execution(PipelineState.GENERATING_REPORT)
        exec_ = PipelineExecution(
            pipeline_id=exec_.pipeline_id,
            target=exec_.target,
            state=exec_.state,
            stages=exec_.stages,
            result=PipelineResult(job_id="job-1", queue_entry_id="q-1", findings_count=3, report_id="report-1"),
            owner_user_id=exec_.owner_user_id,
            scanner_ids=exec_.scanner_ids,
            priority=exec_.priority,
        )
        result = orchestrator.advance(exec_)
        assert result.state == PipelineState.SENDING_NOTIFICATION
        notification_service.send.assert_called_once()
        assert len(result.result.notification_ids) > 0

    def test_advance_to_completed(self, orchestrator) -> None:
        exec_ = _make_execution(PipelineState.SENDING_NOTIFICATION)
        exec_ = PipelineExecution(
            pipeline_id=exec_.pipeline_id,
            target=exec_.target,
            state=exec_.state,
            stages=exec_.stages,
            result=PipelineResult(
                job_id="job-1",
                queue_entry_id="q-1",
                findings_count=3,
                report_id="report-1",
                notification_ids=("notif-1",),
            ),
            owner_user_id=exec_.owner_user_id,
            scanner_ids=exec_.scanner_ids,
            priority=exec_.priority,
        )
        result = orchestrator.advance(exec_)
        assert result.state == PipelineState.COMPLETED

    def test_no_advance_from_completed(self, orchestrator) -> None:
        exec_ = _make_execution(PipelineState.COMPLETED)
        result = orchestrator.advance(exec_)
        assert result.state == PipelineState.COMPLETED


class TestCancel:
    def test_cancel_sets_state(self, orchestrator) -> None:
        exec_ = _make_execution(PipelineState.RUNNING)
        result = orchestrator.cancel(exec_)
        assert result.state == PipelineState.CANCELLED
        assert result.result.error_message == "Pipeline cancelled"


class TestRetry:
    def test_retry_clears_error(self, orchestrator) -> None:
        exec_ = _make_execution(PipelineState.FAILED)
        exec_ = PipelineExecution(
            pipeline_id=exec_.pipeline_id,
            target=exec_.target,
            state=PipelineState.FAILED,
            stages=exec_.stages,
            result=PipelineResult(error_message="Something failed"),
            owner_user_id=exec_.owner_user_id,
            scanner_ids=exec_.scanner_ids,
            priority=exec_.priority,
        )
        result = orchestrator.retry(exec_)
        assert result.result.error_message == ""
        assert result.state == PipelineState.FAILED


class TestFailures:
    def test_collecting_results_failure_transitions_to_failed(self, orchestrator, job_service) -> None:
        job_service.get_job_result.side_effect = Exception("Scan failed")
        exec_ = _make_execution(PipelineState.RUNNING)
        exec_ = PipelineExecution(
            pipeline_id=exec_.pipeline_id,
            target=exec_.target,
            state=exec_.state,
            stages=exec_.stages,
            result=PipelineResult(job_id="job-1", queue_entry_id="q-1"),
            owner_user_id=exec_.owner_user_id,
            scanner_ids=exec_.scanner_ids,
            priority=exec_.priority,
        )
        result = orchestrator.advance(exec_)
        assert result.state == PipelineState.FAILED
        assert "Scan failed" in result.result.error_message


class TestPauseResume:
    def test_pause_returns_same(self, orchestrator) -> None:
        exec_ = _make_execution(PipelineState.RUNNING)
        result = orchestrator.pause(exec_)
        assert result.state == PipelineState.RUNNING

    def test_resume_returns_same(self, orchestrator) -> None:
        exec_ = _make_execution(PipelineState.RUNNING)
        result = orchestrator.resume(exec_)
        assert result.state == PipelineState.RUNNING
