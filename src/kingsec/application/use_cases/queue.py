from __future__ import annotations

from typing import Any

from kingsec.application.ports.outbound import QueueRepositoryPort, SchedulerPolicyPort
from kingsec.domain.queue import (
    ConcurrencyPolicy,
    QueueEntry,
    QueuePriority,
    QueueState,
    QueueStatistics,
    ResourceRequirements,
)


class EnqueueJob:
    def __init__(self, repo: QueueRepositoryPort) -> None:
        self._repo = repo
        self._counter = 0

    def execute(
        self,
        payload: str,
        target: str,
        priority: str = "normal",
        scanner_ids: list[str] | None = None,
        owner_user_id: str = "",
        estimated_duration_seconds: int = 300,
    ) -> QueueEntry:
        self._counter += 1
        entry_id = f"q-{self._counter}"
        priority_enum = QueuePriority.NORMAL
        for p in QueuePriority:
            if p.name.lower() == priority.lower():
                priority_enum = p
                break

        entry = QueueEntry(
            entry_id=entry_id,
            job_id=f"job-{entry_id}",
            priority=priority_enum,
            state=QueueState.WAITING,
            payload=payload,
            target=target,
            scanner_ids=tuple(scanner_ids or []),
            owner_user_id=owner_user_id,
            estimated_duration_seconds=estimated_duration_seconds,
            resource_requirements=ResourceRequirements(
                estimated_runtime_seconds=estimated_duration_seconds,
            ),
            concurrency_policy=ConcurrencyPolicy(),
        )
        self._repo.enqueue(entry)
        return entry


class DequeueJob:
    def __init__(self, repo: QueueRepositoryPort) -> None:
        self._repo = repo

    def execute(self, entry_id: str) -> QueueEntry:
        entry = self._repo.dequeue(entry_id)
        if not entry:
            from kingsec.application.errors import QueueEntryNotFoundError

            raise QueueEntryNotFoundError(f"Queue entry '{entry_id}' not found")
        return entry


class PeekJob:
    """Look up a queue entry without removing it - the read-only counterpart to DequeueJob."""

    def __init__(self, repo: QueueRepositoryPort) -> None:
        self._repo = repo

    def execute(self, entry_id: str) -> QueueEntry:
        entry = self._repo.peek(entry_id)
        if not entry:
            from kingsec.application.errors import QueueEntryNotFoundError

            raise QueueEntryNotFoundError(f"Queue entry '{entry_id}' not found")
        return entry


class CancelQueuedJob:
    def __init__(self, repo: QueueRepositoryPort) -> None:
        self._repo = repo

    def execute(self, entry_id: str) -> None:
        entry = self._repo.peek(entry_id)
        if not entry:
            from kingsec.application.errors import QueueEntryNotFoundError

            raise QueueEntryNotFoundError(f"Queue entry '{entry_id}' not found")
        cancelled = QueueEntry(
            entry_id=entry.entry_id,
            job_id=entry.job_id,
            priority=entry.priority,
            state=QueueState.CANCELLED,
            strategy=entry.strategy,
            payload=entry.payload,
            target=entry.target,
            scanner_ids=entry.scanner_ids,
            resource_requirements=entry.resource_requirements,
            concurrency_policy=entry.concurrency_policy,
            owner_user_id=entry.owner_user_id,
            assigned_agent_id=entry.assigned_agent_id,
            retry_count=entry.retry_count,
            max_retries=entry.max_retries,
            depend_on_entry_ids=entry.depend_on_entry_ids,
            created_at=entry.created_at,
            updated_at=entry.updated_at,
            position=entry.position,
            error_message="",
        )
        self._repo.update(cancelled)


class PauseQueue:
    def __init__(self, repo: QueueRepositoryPort) -> None:
        self._repo = repo

    def execute(self) -> None:
        self._repo.pause()


class ResumeQueue:
    def __init__(self, repo: QueueRepositoryPort) -> None:
        self._repo = repo

    def execute(self) -> None:
        self._repo.resume()


class ListQueue:
    def __init__(self, repo: QueueRepositoryPort) -> None:
        self._repo = repo

    def execute(self) -> list[QueueEntry]:
        return self._repo.find_all()


class GetQueueStatistics:
    def __init__(self, repo: QueueRepositoryPort) -> None:
        self._repo = repo

    def execute(self) -> QueueStatistics:
        return self._repo.statistics()


class ChangePriority:
    def __init__(self, repo: QueueRepositoryPort) -> None:
        self._repo = repo

    def execute(self, entry_id: str, priority: str) -> QueueEntry:
        entry = self._repo.peek(entry_id)
        if not entry:
            from kingsec.application.errors import QueueEntryNotFoundError

            raise QueueEntryNotFoundError(f"Queue entry '{entry_id}' not found")
        new_priority = QueuePriority.NORMAL
        for p in QueuePriority:
            if p.name.lower() == priority.lower():
                new_priority = p
                break
        updated = QueueEntry(
            entry_id=entry.entry_id,
            job_id=entry.job_id,
            priority=new_priority,
            state=entry.state,
            strategy=entry.strategy,
            payload=entry.payload,
            target=entry.target,
            scanner_ids=entry.scanner_ids,
            resource_requirements=entry.resource_requirements,
            concurrency_policy=entry.concurrency_policy,
            owner_user_id=entry.owner_user_id,
            assigned_agent_id=entry.assigned_agent_id,
            retry_count=entry.retry_count,
            max_retries=entry.max_retries,
            depend_on_entry_ids=entry.depend_on_entry_ids,
            created_at=entry.created_at,
            updated_at=entry.updated_at,
            position=entry.position,
            error_message="",
        )
        self._repo.update(updated)
        return updated


class MoveQueuePosition:
    def __init__(self, repo: QueueRepositoryPort) -> None:
        self._repo = repo

    def execute(self, entry_id: str, new_position: int) -> QueueEntry:
        entry = self._repo.peek(entry_id)
        if not entry:
            from kingsec.application.errors import QueueEntryNotFoundError

            raise QueueEntryNotFoundError(f"Queue entry '{entry_id}' not found")
        all_entries = self._repo.find_all()
        sorted_entries = sorted(all_entries, key=lambda e: (e.priority, e.created_at))
        current_idx = next((i for i, e in enumerate(sorted_entries) if e.entry_id == entry_id), -1)
        if current_idx == -1:
            return entry
        sorted_entries.pop(current_idx)
        new_idx = max(0, min(new_position, len(sorted_entries)))
        sorted_entries.insert(new_idx, entry)
        for i, e in enumerate(sorted_entries):
            re_positioned = QueueEntry(
                entry_id=e.entry_id,
                job_id=e.job_id,
                priority=e.priority,
                state=e.state,
                strategy=e.strategy,
                payload=e.payload,
                target=e.target,
                scanner_ids=e.scanner_ids,
                resource_requirements=e.resource_requirements,
                concurrency_policy=e.concurrency_policy,
                owner_user_id=e.owner_user_id,
                assigned_agent_id=e.assigned_agent_id,
                retry_count=e.retry_count,
                max_retries=e.max_retries,
                depend_on_entry_ids=e.depend_on_entry_ids,
                created_at=e.created_at,
                updated_at=e.updated_at,
                position=i + 1,
                error_message="",
            )
            self._repo.update(re_positioned)
        return self._repo.peek(entry_id) or entry


class AssignBestAgent:
    def __init__(self, repo: QueueRepositoryPort, policy: SchedulerPolicyPort, agent_repo: Any) -> None:
        self._repo = repo
        self._policy = policy
        self._agent_repo = agent_repo

    def execute(self, entry_id: str) -> str | None:
        entry = self._repo.peek(entry_id)
        if not entry:
            from kingsec.application.errors import QueueEntryNotFoundError

            raise QueueEntryNotFoundError(f"Queue entry '{entry_id}' not found")
        agents = self._agent_repo.find_idle()
        agent = self._policy.allocate_agent(entry, agents)
        if not agent:
            return None
        updated = QueueEntry(
            entry_id=entry.entry_id,
            job_id=entry.job_id,
            priority=entry.priority,
            state=QueueState.READY,
            strategy=entry.strategy,
            payload=entry.payload,
            target=entry.target,
            scanner_ids=entry.scanner_ids,
            resource_requirements=entry.resource_requirements,
            concurrency_policy=entry.concurrency_policy,
            owner_user_id=entry.owner_user_id,
            assigned_agent_id=agent.id.value,
            retry_count=entry.retry_count,
            max_retries=entry.max_retries,
            depend_on_entry_ids=entry.depend_on_entry_ids,
            created_at=entry.created_at,
            updated_at=entry.updated_at,
            position=entry.position,
            error_message="",
        )
        self._repo.update(updated)
        return agent.id.value


class GetNextJob:
    """Preview what the scheduler would hand out next - read-only.

    Does not promote a WAITING entry to READY: that transition is a real
    state change and belongs to the actual dispatch path (AssignNextJob),
    not to a preview endpoint. Reports the entry's real current state.
    """

    def __init__(self, repo: QueueRepositoryPort, policy: SchedulerPolicyPort) -> None:
        self._repo = repo
        self._policy = policy

    def execute(self) -> QueueEntry | None:
        ready = self._repo.find_ready()
        if not ready:
            ready_waiting = self._repo.find_waiting()
            if ready_waiting:
                return ready_waiting[0]
        return self._policy.select_next_job(ready)
