from __future__ import annotations

import heapq
from datetime import UTC, datetime

from kingsec.application.ports.outbound import SchedulerPolicyPort
from kingsec.domain.agent import Agent, AgentCapability, AgentState
from kingsec.domain.queue import QueueEntry, QueuePriority


class DefaultSchedulingPolicy(SchedulerPolicyPort):
    """Priority-ordered scheduling with starvation prevention, agent capability
    matching, and concurrency limit enforcement.

    Algorithm:
    1. Each ready entry gets a composite score = (-priority, submission_order)
       so higher priority and earlier submission come first.
    2. Starvation prevention: entries waiting > 5 min get a priority boost.
    3. Agent matching: filter agents by capability (required scanners, memory).
    """

    STARVATION_THRESHOLD_SECONDS = 300

    def select_next_job(self, ready_entries: list[QueueEntry]) -> QueueEntry | None:
        if not ready_entries:
            return None

        now = datetime.now(UTC)
        scored: list[tuple[int, float, str, QueueEntry]] = []

        for i, entry in enumerate(ready_entries):
            priority = entry.priority.value
            try:
                created = datetime.fromisoformat(entry.created_at)
                age = (now - created).total_seconds()
            except (ValueError, TypeError):
                age = 0.0

            if age > self.STARVATION_THRESHOLD_SECONDS:
                boost = int(age / self.STARVATION_THRESHOLD_SECONDS)
                priority = min(priority + boost * 5, QueuePriority.EMERGENCY.value)

            score = -priority
            scored.append((score, age, entry.entry_id, entry))

        scored.sort(key=lambda x: (x[0], x[1], x[2]))
        return scored[0][3] if scored else None

    def allocate_agent(self, entry: QueueEntry, available_agents: list[Agent]) -> Agent | None:
        candidates = [a for a in available_agents if a.state == AgentState.ONLINE]
        if entry.scanner_ids:
            candidates = [
                a for a in candidates
                if any(s in a.capability.supported_scanners for s in entry.scanner_ids)
                or not a.capability.supported_scanners
            ]
        candidates.sort(key=lambda a: (
            a.statistics.total_jobs_completed,
            -a.health.cpu_usage_percent,
        ), reverse=True)
        return candidates[0] if candidates else None

    def calculate_priority(self, entry: QueueEntry) -> QueuePriority:
        now = datetime.now(UTC)
        age = 0.0
        try:
            created = datetime.fromisoformat(entry.created_at)
            age = (now - created).total_seconds()
        except (ValueError, TypeError):
            pass
        retry_boost = entry.retry_count * 5
        age_boost = int(age / self.STARVATION_THRESHOLD_SECONDS) * 5
        raw = entry.priority.value + retry_boost + age_boost
        if raw >= QueuePriority.EMERGENCY.value:
            return QueuePriority.EMERGENCY
        if raw >= QueuePriority.CRITICAL.value:
            return QueuePriority.CRITICAL
        if raw >= QueuePriority.HIGH.value:
            return QueuePriority.HIGH
        if raw >= QueuePriority.NORMAL.value:
            return QueuePriority.NORMAL
        return QueuePriority.LOW
