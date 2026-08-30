from __future__ import annotations

from unittest.mock import MagicMock

import pytest

from kingsec.application.errors import PipelineNotFoundError, PipelineStateConflictError
from kingsec.application.ports.outbound import PipelineOrchestratorPort, PipelineRepositoryPort
from kingsec.application.ports.outbound.audit_publisher import AuditPublisher
from kingsec.application.use_cases.pipeline import (
    CancelPipeline,
    GetPipeline,
    ListPipelines,
    PausePipeline,
    ResumePipeline,
    RetryPipeline,
    StartPipeline,
)
from kingsec.domain.audit import AuditAction
from kingsec.domain.pipeline import (
    PipelineExecution,
    PipelineId,
    PipelineStage,
    PipelineState,
)


@pytest.fixture
def repo() -> MagicMock:
    return MagicMock(spec=PipelineRepositoryPort)


@pytest.fixture
def orchestrator() -> MagicMock:
    return MagicMock(spec=PipelineOrchestratorPort)


@pytest.fixture
def audit() -> MagicMock:
    return MagicMock(spec=AuditPublisher)


class TestStartPipeline:
    def test_start_creates_queued_execution(self, repo, orchestrator, audit) -> None:
        uc = StartPipeline(repo, orchestrator, audit)
        result = uc.execute(target="10.0.0.1", owner_user_id="u1")
        assert result.state == PipelineState.QUEUED
        assert result.target == "10.0.0.1"
        assert result.owner_user_id == "u1"
        repo.save.assert_called_once()
        audit.record.assert_called_once()
        args, _ = audit.record.call_args
        assert args[0].action == AuditAction.PIPELINE_STARTED

    def test_start_with_scanners(self, repo, orchestrator, audit) -> None:
        uc = StartPipeline(repo, orchestrator, audit)
        result = uc.execute(target="example.com", scanner_ids=["nuclei", "gobuster"])
        assert result.scanner_ids == ("nuclei", "gobuster")

    def test_start_increments_id(self, repo, orchestrator, audit) -> None:
        uc = StartPipeline(repo, orchestrator, audit)
        r1 = uc.execute(target="a")
        r2 = uc.execute(target="b")
        assert r1.pipeline_id.value == "pl-1"
        assert r2.pipeline_id.value == "pl-2"


class TestGetPipeline:
    def test_get_existing_by_owner(self, repo) -> None:
        pid = PipelineId(value="pl-1")
        stages = (PipelineStage(name="queued", status="completed"),)
        expected = PipelineExecution(
            pipeline_id=pid,
            target="10.0.0.1",
            state=PipelineState.QUEUED,
            stages=stages,
            owner_user_id="alice",
        )
        repo.find_by_id.return_value = expected
        uc = GetPipeline(repo)
        result = uc.execute("pl-1", requesting_user_id="alice")
        assert result.pipeline_id.value == "pl-1"

    def test_get_missing_raises(self, repo) -> None:
        repo.find_by_id.return_value = None
        uc = GetPipeline(repo)
        with pytest.raises(PipelineNotFoundError):
            uc.execute("pl-missing")

    def test_get_by_admin_succeeds(self, repo) -> None:
        """KSEC-71-01: an admin may read any user's pipeline."""
        pid = PipelineId(value="pl-1")
        expected = PipelineExecution(
            pipeline_id=pid, target="10.0.0.1", state=PipelineState.QUEUED, owner_user_id="alice"
        )
        repo.find_by_id.return_value = expected
        uc = GetPipeline(repo)
        result = uc.execute("pl-1", requesting_user_id="admin1", is_admin=True)
        assert result.pipeline_id.value == "pl-1"

    def test_get_by_non_owner_non_admin_raises_not_found(self, repo) -> None:
        """KSEC-71-01: a non-owner, non-admin cannot read another user's
        pipeline - and the failure is indistinguishable from "not found"."""
        pid = PipelineId(value="pl-1")
        existing = PipelineExecution(
            pipeline_id=pid, target="10.99.99.99", state=PipelineState.QUEUED, owner_user_id="alice"
        )
        repo.find_by_id.return_value = existing
        uc = GetPipeline(repo)
        with pytest.raises(PipelineNotFoundError):
            uc.execute("pl-1", requesting_user_id="mallory")


class TestListPipelines:
    def test_list_by_admin_returns_all(self, repo) -> None:
        repo.find_all.return_value = [
            PipelineExecution(pipeline_id=PipelineId(value="pl-1"), target="a", state=PipelineState.QUEUED),
            PipelineExecution(pipeline_id=PipelineId(value="pl-2"), target="b", state=PipelineState.RUNNING),
        ]
        uc = ListPipelines(repo)
        result = uc.execute(requesting_user_id="admin1", is_admin=True)
        assert len(result) == 2
        repo.find_all.assert_called_once()

    def test_list_empty_for_admin(self, repo) -> None:
        repo.find_all.return_value = []
        uc = ListPipelines(repo)
        assert uc.execute(requesting_user_id="admin1", is_admin=True) == []

    def test_list_by_non_admin_is_scoped_to_owner(self, repo) -> None:
        """KSEC-71-01: a non-admin must never receive another user's
        pipelines through LIST - the repository is queried by owner, not
        filtered client-side after an unscoped find_all()."""
        repo.find_by_owner.return_value = [
            PipelineExecution(pipeline_id=PipelineId(value="pl-1"), target="a", state=PipelineState.QUEUED,
                               owner_user_id="alice"),
        ]
        uc = ListPipelines(repo)
        result = uc.execute(requesting_user_id="alice")
        assert len(result) == 1
        assert result[0].owner_user_id == "alice"
        repo.find_by_owner.assert_called_once_with("alice")
        repo.find_all.assert_not_called()

    def test_list_by_non_admin_empty_when_owner_has_none(self, repo) -> None:
        repo.find_by_owner.return_value = []
        uc = ListPipelines(repo)
        assert uc.execute(requesting_user_id="mallory") == []


class TestCancelPipeline:
    def test_cancel(self, repo, orchestrator, audit) -> None:
        pid = PipelineId(value="pl-1")
        stages = (PipelineStage(name="queued", status="completed"),)
        existing = PipelineExecution(
            pipeline_id=pid,
            target="a",
            state=PipelineState.RUNNING,
            stages=stages,
        )
        repo.find_by_id.return_value = existing
        cancelled = PipelineExecution(
            pipeline_id=pid,
            target="a",
            state=PipelineState.CANCELLED,
            stages=stages,
        )
        orchestrator.cancel.return_value = cancelled
        uc = CancelPipeline(repo, orchestrator, audit)
        result = uc.execute("pl-1")
        assert result.state == PipelineState.CANCELLED
        orchestrator.cancel.assert_called_once_with(existing)
        repo.save.assert_called_once()

    def test_cancel_completed_raises(self, repo, orchestrator, audit) -> None:
        pid = PipelineId(value="pl-1")
        stages = (PipelineStage(name="queued", status="completed"),)
        existing = PipelineExecution(
            pipeline_id=pid,
            target="a",
            state=PipelineState.COMPLETED,
            stages=stages,
        )
        repo.find_by_id.return_value = existing
        uc = CancelPipeline(repo, orchestrator, audit)
        with pytest.raises(PipelineStateConflictError):
            uc.execute("pl-1")

    def test_cancel_missing_raises(self, repo, orchestrator, audit) -> None:
        repo.find_by_id.return_value = None
        uc = CancelPipeline(repo, orchestrator, audit)
        with pytest.raises(PipelineNotFoundError):
            uc.execute("pl-missing")


class TestRetryPipeline:
    def test_retry_failed(self, repo, orchestrator, audit) -> None:
        pid = PipelineId(value="pl-1")
        stages = (PipelineStage(name="queued", status="completed"),)
        existing = PipelineExecution(
            pipeline_id=pid,
            target="a",
            state=PipelineState.FAILED,
            stages=stages,
        )
        repo.find_by_id.return_value = existing
        retried = PipelineExecution(
            pipeline_id=pid,
            target="a",
            state=PipelineState.FAILED,
            stages=stages,
        )
        orchestrator.retry.return_value = retried
        uc = RetryPipeline(repo, orchestrator, audit)
        result = uc.execute("pl-1")
        assert result.state == PipelineState.FAILED
        audit.record.assert_called_once()

    def test_retry_non_failed_raises(self, repo, orchestrator, audit) -> None:
        pid = PipelineId(value="pl-1")
        stages = (PipelineStage(name="queued", status="completed"),)
        existing = PipelineExecution(
            pipeline_id=pid,
            target="a",
            state=PipelineState.RUNNING,
            stages=stages,
        )
        repo.find_by_id.return_value = existing
        uc = RetryPipeline(repo, orchestrator, audit)
        with pytest.raises(PipelineStateConflictError):
            uc.execute("pl-1")


class TestPausePipeline:
    def test_pause_not_supported(self, repo, orchestrator, audit) -> None:
        """Pausing has no real backing state (no PAUSED value in PipelineState,
        no code path checks one) — it must raise rather than silently no-op
        and claim success."""
        pid = PipelineId(value="pl-1")
        stages = (PipelineStage(name="queued", status="completed"),)
        existing = PipelineExecution(
            pipeline_id=pid,
            target="a",
            state=PipelineState.RUNNING,
            stages=stages,
        )
        repo.find_by_id.return_value = existing
        uc = PausePipeline(repo, orchestrator, audit)
        with pytest.raises(PipelineStateConflictError):
            uc.execute("pl-1")
        repo.save.assert_not_called()
        audit.record.assert_not_called()


class TestResumePipeline:
    def test_resume_not_supported(self, repo, orchestrator, audit) -> None:
        """Resuming has no real backing state (no PAUSED value in
        PipelineState, no code path checks one) — it must raise rather than
        silently no-op and claim success."""
        pid = PipelineId(value="pl-1")
        stages = (PipelineStage(name="queued", status="completed"),)
        existing = PipelineExecution(
            pipeline_id=pid,
            target="a",
            state=PipelineState.RUNNING,
            stages=stages,
        )
        repo.find_by_id.return_value = existing
        uc = ResumePipeline(repo, orchestrator, audit)
        with pytest.raises(PipelineStateConflictError):
            uc.execute("pl-1")
        repo.save.assert_not_called()
        audit.record.assert_not_called()
