from __future__ import annotations

from unittest.mock import MagicMock

import pytest

from kingsec.application.errors import QueueEntryNotFoundError
from kingsec.application.ports.outbound.queue_repository import QueueRepositoryPort
from kingsec.application.use_cases.queue import GetNextJob, PauseQueue, PeekJob, ResumeQueue
from kingsec.domain.queue import QueueEntry, QueuePriority, QueueState


@pytest.fixture
def repo() -> MagicMock:
    return MagicMock(spec=QueueRepositoryPort)


class TestPauseQueue:
    def test_pause_calls_repo(self, repo: MagicMock) -> None:
        PauseQueue(repo).execute()
        repo.pause.assert_called_once()


class TestResumeQueue:
    def test_resume_calls_repo(self, repo: MagicMock) -> None:
        ResumeQueue(repo).execute()
        repo.resume.assert_called_once()


def _make_entry(entry_id: str = "q-1", state: QueueState = QueueState.WAITING) -> QueueEntry:
    return QueueEntry(
        entry_id=entry_id,
        job_id=f"job-{entry_id}",
        priority=QueuePriority.NORMAL,
        state=state,
        payload="payload",
        target="10.0.0.1",
    )


class TestPeekJob:
    def test_peek_returns_entry_without_removing_it(self, repo: MagicMock) -> None:
        entry = _make_entry()
        repo.peek.return_value = entry

        result = PeekJob(repo).execute("q-1")

        assert result is entry
        repo.peek.assert_called_once_with("q-1")
        repo.dequeue.assert_not_called()

    def test_peek_missing_entry_raises(self, repo: MagicMock) -> None:
        repo.peek.return_value = None

        with pytest.raises(QueueEntryNotFoundError):
            PeekJob(repo).execute("does-not-exist")


class TestGetNextJob:
    def test_no_ready_or_waiting_entries_returns_none(self, repo: MagicMock) -> None:
        repo.find_ready.return_value = []
        repo.find_waiting.return_value = []
        policy = MagicMock()
        policy.select_next_job.return_value = None

        result = GetNextJob(repo, policy).execute()

        assert result is None
        repo.update.assert_not_called()

    def test_waiting_entry_previewed_without_being_promoted_or_persisted(self, repo: MagicMock) -> None:
        waiting_entry = _make_entry(state=QueueState.WAITING)
        repo.find_ready.return_value = []
        repo.find_waiting.return_value = [waiting_entry]
        policy = MagicMock()

        result = GetNextJob(repo, policy).execute()

        # Reports the entry as it actually is - still WAITING - and never
        # writes anything back. Promoting it to READY is the dispatch
        # path's job (AssignNextJob), not a side effect of previewing it.
        assert result is waiting_entry
        assert result.state == QueueState.WAITING
        repo.update.assert_not_called()

    def test_ready_entry_delegates_to_scheduler_policy(self, repo: MagicMock) -> None:
        ready_entry = _make_entry(state=QueueState.READY)
        repo.find_ready.return_value = [ready_entry]
        policy = MagicMock()
        policy.select_next_job.return_value = ready_entry

        result = GetNextJob(repo, policy).execute()

        assert result is ready_entry
        policy.select_next_job.assert_called_once_with([ready_entry])
        repo.update.assert_not_called()
