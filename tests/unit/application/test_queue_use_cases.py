from __future__ import annotations

from unittest.mock import MagicMock

import pytest

from kingsec.application.ports.outbound.queue_repository import QueueRepositoryPort
from kingsec.application.use_cases.queue import PauseQueue, ResumeQueue


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
