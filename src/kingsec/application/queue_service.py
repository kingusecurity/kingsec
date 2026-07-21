from __future__ import annotations

from typing import Any

from kingsec.application.ports.outbound import QueueRepositoryPort, SchedulerPolicyPort
from kingsec.application.ports.queue_service import QueueServicePort
from kingsec.application.use_cases.queue import (
    AssignBestAgent,
    CancelQueuedJob,
    ChangePriority,
    DequeueJob,
    EnqueueJob,
    GetNextJob,
    GetQueueStatistics,
    ListQueue,
    MoveQueuePosition,
    PauseQueue,
    ResumeQueue,
)
from kingsec.domain.queue import QueueEntry, QueueStatistics


class QueueService(QueueServicePort):
    def __init__(self, repo: QueueRepositoryPort, policy: SchedulerPolicyPort,
                 agent_repo: Any = None) -> None:
        self._enqueue_uc = EnqueueJob(repo)
        self._dequeue_uc = DequeueJob(repo)
        self._cancel_uc = CancelQueuedJob(repo)
        self._pause_uc = PauseQueue(repo)
        self._resume_uc = ResumeQueue(repo)
        self._list_uc = ListQueue(repo)
        self._stats_uc = GetQueueStatistics(repo)
        self._priority_uc = ChangePriority(repo)
        self._move_uc = MoveQueuePosition(repo)
        self._assign_uc = AssignBestAgent(repo, policy, agent_repo) if agent_repo else None
        self._next_uc = GetNextJob(repo, policy)

    def enqueue(self, payload: str, target: str, priority: str = "normal",
                scanner_ids: list[str] | None = None,
                owner_user_id: str = "",
                estimated_duration_seconds: int = 300) -> QueueEntry:
        return self._enqueue_uc.execute(payload, target, priority, scanner_ids,
                                         owner_user_id, estimated_duration_seconds)

    def dequeue(self, entry_id: str) -> QueueEntry:
        return self._dequeue_uc.execute(entry_id)

    def cancel(self, entry_id: str) -> None:
        self._cancel_uc.execute(entry_id)

    def pause(self) -> None:
        self._pause_uc.execute()

    def resume(self) -> None:
        self._resume_uc.execute()

    def list_queue(self) -> list[QueueEntry]:
        return self._list_uc.execute()

    def get_statistics(self) -> QueueStatistics:
        return self._stats_uc.execute()

    def change_priority(self, entry_id: str, priority: str) -> QueueEntry:
        return self._priority_uc.execute(entry_id, priority)

    def move_position(self, entry_id: str, new_position: int) -> QueueEntry:
        return self._move_uc.execute(entry_id, new_position)

    def assign_best_agent(self, entry_id: str) -> str | None:
        if not self._assign_uc:
            return None
        return self._assign_uc.execute(entry_id)

    def get_next(self) -> QueueEntry | None:
        return self._next_uc.execute()
