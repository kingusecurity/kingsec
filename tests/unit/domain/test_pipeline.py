from __future__ import annotations

from kingsec.domain.pipeline import (
    PIPELINE_ORDER,
    PipelineExecution,
    PipelineId,
    PipelineResult,
    PipelineStage,
    PipelineState,
)


class TestPipelineId:
    def test_value(self) -> None:
        pid = PipelineId(value="pl-1")
        assert pid.value == "pl-1"
        assert str(pid) == "pl-1"


class TestPipelineState:
    def test_values(self) -> None:
        assert PipelineState.QUEUED.value == "queued"
        assert PipelineState.ASSIGNED.value == "assigned"
        assert PipelineState.RUNNING.value == "running"
        assert PipelineState.COLLECTING_RESULTS.value == "collecting_results"
        assert PipelineState.GENERATING_REPORT.value == "generating_report"
        assert PipelineState.SENDING_NOTIFICATION.value == "sending_notification"
        assert PipelineState.COMPLETED.value == "completed"
        assert PipelineState.FAILED.value == "failed"
        assert PipelineState.CANCELLED.value == "cancelled"


class TestPipelineOrder:
    def test_order(self) -> None:
        assert PIPELINE_ORDER == [
            PipelineState.QUEUED,
            PipelineState.ASSIGNED,
            PipelineState.RUNNING,
            PipelineState.COLLECTING_RESULTS,
            PipelineState.GENERATING_REPORT,
            PipelineState.SENDING_NOTIFICATION,
            PipelineState.COMPLETED,
        ]


class TestPipelineStage:
    def test_defaults(self) -> None:
        s = PipelineStage(name="queued")
        assert s.name == "queued"
        assert s.status == "pending"
        assert s.started_at == ""
        assert s.completed_at == ""
        assert s.error_message == ""

    def test_full_construction(self) -> None:
        s = PipelineStage(
            name="running",
            status="completed",
            started_at="2025-01-01T00:00:00",
            completed_at="2025-01-01T01:00:00",
            error_message="",
        )
        assert s.name == "running"
        assert s.status == "completed"


class TestPipelineResult:
    def test_defaults(self) -> None:
        r = PipelineResult()
        assert r.job_id == ""
        assert r.findings_count == 0
        assert r.notification_ids == ()

    def test_full_construction(self) -> None:
        r = PipelineResult(
            job_id="job-1",
            queue_entry_id="q-1",
            agent_id="agent-1",
            report_id="report-1",
            notification_ids=("n-1", "n-2"),
            findings_count=5,
            summary="Found 5 issues",
            error_message="",
        )
        assert r.job_id == "job-1"
        assert r.findings_count == 5
        assert r.summary == "Found 5 issues"


class TestPipelineExecution:
    def test_defaults(self) -> None:
        pid = PipelineId(value="pl-1")
        stages = (PipelineStage(name="queued", status="completed"),)
        exec_ = PipelineExecution(
            pipeline_id=pid,
            target="10.0.0.1",
            state=PipelineState.QUEUED,
            stages=stages,
        )
        assert exec_.pipeline_id.value == "pl-1"
        assert exec_.target == "10.0.0.1"
        assert exec_.state == PipelineState.QUEUED
        assert exec_.owner_user_id == ""
        assert exec_.result.job_id == ""

    def test_with_result(self) -> None:
        pid = PipelineId(value="pl-2")
        stages = (
            PipelineStage(name="queued", status="completed"),
            PipelineStage(name="running", status="completed"),
        )
        result = PipelineResult(job_id="job-99", findings_count=3)
        exec_ = PipelineExecution(
            pipeline_id=pid,
            target="example.com",
            state=PipelineState.RUNNING,
            stages=stages,
            result=result,
            owner_user_id="u1",
            scanner_ids=("nuclei",),
            priority="high",
        )
        assert exec_.owner_user_id == "u1"
        assert exec_.scanner_ids == ("nuclei",)
        assert exec_.priority == "high"
        assert exec_.result.job_id == "job-99"
        assert exec_.result.findings_count == 3

    def test_immutable(self) -> None:
        pid = PipelineId(value="pl-3")
        exec_ = PipelineExecution(
            pipeline_id=pid,
            target="test",
            state=PipelineState.QUEUED,
        )
        import pytest

        with pytest.raises(AttributeError):
            exec_.target = "new-target"
