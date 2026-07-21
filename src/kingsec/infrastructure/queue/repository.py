from __future__ import annotations

from datetime import UTC, datetime
from typing import Any

from kingsec.application.ports.outbound import QueueRepositoryPort
from kingsec.domain.queue import (
    QueueEntry,
    QueuePriority,
    QueueState,
    QueueStatistics,
)


class InMemoryQueueRepository(QueueRepositoryPort):
    def __init__(self) -> None:
        self._entries: dict[str, QueueEntry] = {}
        self._paused: bool = False

    def enqueue(self, entry: QueueEntry) -> None:
        self._entries[entry.entry_id] = entry

    def dequeue(self, entry_id: str) -> QueueEntry | None:
        entry = self._entries.pop(entry_id, None)
        return entry

    def peek(self, entry_id: str) -> QueueEntry | None:
        return self._entries.get(entry_id)

    def remove(self, entry_id: str) -> None:
        self._entries.pop(entry_id, None)

    def find_ready(self) -> list[QueueEntry]:
        return [e for e in self._entries.values() if e.state == QueueState.READY and not self._paused]

    def find_waiting(self) -> list[QueueEntry]:
        return [e for e in self._entries.values() if e.state == QueueState.WAITING and not self._paused]

    def find_running(self) -> list[QueueEntry]:
        return [e for e in self._entries.values() if e.state == QueueState.RUNNING]

    def find_all(self) -> list[QueueEntry]:
        return list(self._entries.values())

    def update(self, entry: QueueEntry) -> None:
        self._entries[entry.entry_id] = entry

    def statistics(self) -> QueueStatistics:
        all_e = list(self._entries.values())
        waiting = sum(1 for e in all_e if e.state == QueueState.WAITING)
        ready = sum(1 for e in all_e if e.state == QueueState.READY)
        running = sum(1 for e in all_e if e.state == QueueState.RUNNING)
        blocked = sum(1 for e in all_e if e.state == QueueState.BLOCKED)
        completed = sum(1 for e in all_e if e.state == QueueState.COMPLETED)
        failed = sum(1 for e in all_e if e.state == QueueState.FAILED)
        cancelled = sum(1 for e in all_e if e.state == QueueState.CANCELLED)
        now = datetime.now(UTC)
        wait_times: list[float] = []
        oldest = 0.0
        for e in all_e:
            try:
                created = datetime.fromisoformat(e.created_at)
                age = (now - created).total_seconds()
                wait_times.append(age)
                if age > oldest:
                    oldest = age
            except (ValueError, TypeError):
                pass
        avg_wait = sum(wait_times) / len(wait_times) if wait_times else 0.0
        longest = max(wait_times) if wait_times else 0.0
        return QueueStatistics(
            total_entries=len(all_e),
            waiting=waiting,
            ready=ready,
            running=running,
            blocked=blocked,
            completed=completed,
            failed=failed,
            cancelled=cancelled,
            average_wait_time_seconds=avg_wait,
            longest_wait_time_seconds=longest,
            oldest_entry_age_seconds=oldest,
            queue_full=len(all_e) >= 1000,
            paused=self._paused,
        )


class SQLAlchemyQueueRepository(QueueRepositoryPort):
    def __init__(self, session_factory: Any) -> None:
        self._session_factory = session_factory

    def enqueue(self, entry: QueueEntry) -> None:
        from sqlalchemy import text
        with self._session_factory() as session:
            session.execute(
                text("""
                    INSERT INTO scan_queue (entry_id, job_id, priority, state, payload, target,
                        owner_user_id, assigned_agent_id, retry_count, created_at)
                    VALUES (:entry_id, :job_id, :priority, :state, :payload, :target,
                        :owner_user_id, :assigned_agent_id, :retry_count, :created_at)
                """),
                {
                    "entry_id": entry.entry_id,
                    "job_id": entry.job_id,
                    "priority": entry.priority.value,
                    "state": entry.state.value,
                    "payload": entry.payload,
                    "target": entry.target,
                    "owner_user_id": entry.owner_user_id,
                    "assigned_agent_id": entry.assigned_agent_id,
                    "retry_count": entry.retry_count,
                    "created_at": entry.created_at,
                },
            )
            session.commit()

    def dequeue(self, entry_id: str) -> QueueEntry | None:
        from sqlalchemy import text
        with self._session_factory() as session:
            row = session.execute(
                text("SELECT * FROM scan_queue WHERE entry_id = :entry_id"),
                {"entry_id": entry_id},
            ).fetchone()
            if not row:
                return None
            session.execute(
                text("DELETE FROM scan_queue WHERE entry_id = :entry_id"),
                {"entry_id": entry_id},
            )
            session.commit()
            return self._row_to_entry(row._mapping)

    def peek(self, entry_id: str) -> QueueEntry | None:
        from sqlalchemy import text
        with self._session_factory() as session:
            row = session.execute(
                text("SELECT * FROM scan_queue WHERE entry_id = :entry_id"),
                {"entry_id": entry_id},
            ).fetchone()
            if not row:
                return None
            return self._row_to_entry(row._mapping)

    def remove(self, entry_id: str) -> None:
        from sqlalchemy import text
        with self._session_factory() as session:
            session.execute(text("DELETE FROM scan_queue WHERE entry_id = :entry_id"), {"entry_id": entry_id})
            session.commit()

    def find_ready(self) -> list[QueueEntry]:
        return self._find_by_state("ready")

    def find_waiting(self) -> list[QueueEntry]:
        return self._find_by_state("waiting")

    def find_running(self) -> list[QueueEntry]:
        return self._find_by_state("running")

    def find_all(self) -> list[QueueEntry]:
        from sqlalchemy import text
        with self._session_factory() as session:
            rows = session.execute(text("SELECT * FROM scan_queue ORDER BY created_at DESC")).fetchall()
            return [self._row_to_entry(r._mapping) for r in rows]

    def update(self, entry: QueueEntry) -> None:
        from sqlalchemy import text
        with self._session_factory() as session:
            session.execute(
                text("""
                    UPDATE scan_queue SET priority=:priority, state=:state,
                        assigned_agent_id=:assigned_agent_id, retry_count=:retry_count
                    WHERE entry_id=:entry_id
                """),
                {
                    "entry_id": entry.entry_id,
                    "priority": entry.priority.value,
                    "state": entry.state.value,
                    "assigned_agent_id": entry.assigned_agent_id,
                    "retry_count": entry.retry_count,
                },
            )
            session.commit()

    def statistics(self) -> QueueStatistics:
        from datetime import UTC, datetime

        from sqlalchemy import text

        with self._session_factory() as session:
            # Single GROUP BY query for state counts
            state_rows = session.execute(
                text("SELECT state, COUNT(*) as cnt FROM scan_queue GROUP BY state")
            ).fetchall()
            state_counts: dict[str, int] = {}
            for r in state_rows:
                state_counts[r.state] = r.cnt

            # Compute wait times from created_at only (no full-row fetch)
            ts_rows = session.execute(
                text("SELECT created_at FROM scan_queue")
            ).fetchall()

        now = datetime.now(UTC)
        wait_times: list[float] = [
            (now - datetime.fromisoformat(r.created_at)).total_seconds()
            for r in ts_rows
            if r.created_at
        ]
        avg_wait = sum(wait_times) / len(wait_times) if wait_times else 0.0
        longest = max(wait_times) if wait_times else 0.0

        return QueueStatistics(
            total_entries=sum(state_counts.values()),
            waiting=state_counts.get("waiting", 0),
            ready=state_counts.get("ready", 0),
            running=state_counts.get("running", 0),
            blocked=state_counts.get("blocked", 0),
            completed=state_counts.get("completed", 0),
            failed=state_counts.get("failed", 0),
            cancelled=state_counts.get("cancelled", 0),
            average_wait_time_seconds=avg_wait,
            longest_wait_time_seconds=longest,
            oldest_entry_age_seconds=longest,
        )

    def _find_by_state(self, state: str) -> list[QueueEntry]:
        from sqlalchemy import text
        with self._session_factory() as session:
            rows = session.execute(
                text("SELECT * FROM scan_queue WHERE state = :state ORDER BY priority DESC, created_at ASC"),
                {"state": state},
            ).fetchall()
            return [self._row_to_entry(r._mapping) for r in rows]

    def _row_to_entry(self, row: Any) -> QueueEntry:
        return QueueEntry(
            entry_id=row.get("entry_id", ""),
            job_id=row.get("job_id", ""),
            priority=QueuePriority(int(row.get("priority", 20))),
            state=QueueState(row.get("state", "waiting")),
            payload=row.get("payload", ""),
            target=row.get("target", ""),
            owner_user_id=row.get("owner_user_id", ""),
            assigned_agent_id=row.get("assigned_agent_id", ""),
            retry_count=row.get("retry_count", 0),
            created_at=row.get("created_at", ""),
        )
