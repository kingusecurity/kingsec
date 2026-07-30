from __future__ import annotations

import time

from kingsec.application.ports.outbound import AgentDispatcherPort, AgentRepositoryPort
from kingsec.domain.agent import (
    Agent,
    AgentHealth,
    AgentHeartbeat,
    AgentId,
    AgentRegistration,
    AgentState,
    AgentStatistics,
)


class RegisterAgent:
    def __init__(self, repo: AgentRepositoryPort, dispatcher: AgentDispatcherPort) -> None:
        self._repo = repo
        self._dispatcher = dispatcher

    def execute(self, registration: AgentRegistration) -> Agent:
        agent = Agent(
            id=registration.agent_id,
            name=registration.name,
            platform=registration.platform,
            architecture=registration.architecture,
            version=registration.version,
            hostname=registration.hostname,
            state=AgentState.ONLINE,
            capability=registration.capability,
            api_key_hash=registration.api_key_hash,
            health=AgentHealth(),
            statistics=AgentStatistics(),
            registered_at=registration.registered_at,
            last_heartbeat_at=registration.registered_at,
        )
        self._repo.register(agent)
        self._dispatcher.register(agent)
        return agent


class UpdateHeartbeat:
    def __init__(self, repo: AgentRepositoryPort) -> None:
        self._repo = repo

    def execute(self, heartbeat: AgentHeartbeat) -> None:
        agent = self._repo.find_by_id(heartbeat.agent_id)
        if not agent:
            from kingsec.application.errors import AgentNotFoundError

            raise AgentNotFoundError(f"Agent '{heartbeat.agent_id}' not found")

        stats = AgentStatistics(
            total_jobs_assigned=agent.statistics.total_jobs_assigned,
            total_jobs_completed=agent.statistics.total_jobs_completed + heartbeat.jobs_completed,
            total_jobs_failed=agent.statistics.total_jobs_failed + heartbeat.jobs_failed,
            uptime_seconds=heartbeat.health.uptime_seconds,
            last_heartbeat_at=heartbeat.timestamp,
        )
        updated = Agent(
            id=agent.id,
            name=agent.name,
            platform=agent.platform,
            architecture=agent.architecture,
            version=agent.version,
            hostname=agent.hostname,
            state=heartbeat.state,
            capability=agent.capability,
            api_key_hash=agent.api_key_hash,
            health=heartbeat.health,
            statistics=stats,
            current_job_id=heartbeat.current_job_id,
            registered_at=agent.registered_at,
            last_heartbeat_at=heartbeat.timestamp,
            tags=agent.tags,
        )
        self._repo.update(updated)


class ListAgents:
    def __init__(self, repo: AgentRepositoryPort) -> None:
        self._repo = repo

    def execute(self) -> list[Agent]:
        return self._repo.find_all()


class GetAgent:
    def __init__(self, repo: AgentRepositoryPort) -> None:
        self._repo = repo

    def execute(self, agent_id: str) -> Agent | None:
        return self._repo.find_by_id(AgentId(agent_id))


class DisableAgent:
    def __init__(self, repo: AgentRepositoryPort) -> None:
        self._repo = repo

    def execute(self, agent_id: str) -> Agent:
        agent = self._find(agent_id)
        updated = Agent(
            id=agent.id,
            name=agent.name,
            platform=agent.platform,
            architecture=agent.architecture,
            version=agent.version,
            hostname=agent.hostname,
            state=AgentState.DISABLED,
            capability=agent.capability,
            api_key_hash=agent.api_key_hash,
            health=agent.health,
            statistics=agent.statistics,
            current_job_id=agent.current_job_id,
            registered_at=agent.registered_at,
            last_heartbeat_at=agent.last_heartbeat_at,
            tags=agent.tags,
        )
        self._repo.update(updated)
        return updated

    def _find(self, agent_id: str) -> Agent:
        agent = self._repo.find_by_id(AgentId(agent_id))
        if not agent:
            from kingsec.application.errors import AgentNotFoundError

            raise AgentNotFoundError(f"Agent '{agent_id}' not found")
        return agent


class EnableAgent:
    def __init__(self, repo: AgentRepositoryPort) -> None:
        self._repo = repo

    def execute(self, agent_id: str) -> Agent:
        agent = self._find(agent_id)
        updated = Agent(
            id=agent.id,
            name=agent.name,
            platform=agent.platform,
            architecture=agent.architecture,
            version=agent.version,
            hostname=agent.hostname,
            state=AgentState.ONLINE,
            capability=agent.capability,
            api_key_hash=agent.api_key_hash,
            health=agent.health,
            statistics=agent.statistics,
            current_job_id=agent.current_job_id,
            registered_at=agent.registered_at,
            last_heartbeat_at=agent.last_heartbeat_at,
            tags=agent.tags,
        )
        self._repo.update(updated)
        return updated

    def _find(self, agent_id: str) -> Agent:
        agent = self._repo.find_by_id(AgentId(agent_id))
        if not agent:
            from kingsec.application.errors import AgentNotFoundError

            raise AgentNotFoundError(f"Agent '{agent_id}' not found")
        return agent


class RemoveAgent:
    def __init__(self, repo: AgentRepositoryPort) -> None:
        self._repo = repo

    def execute(self, agent_id: str) -> None:
        agent = self._repo.find_by_id(AgentId(agent_id))
        if not agent:
            from kingsec.application.errors import AgentNotFoundError

            raise AgentNotFoundError(f"Agent '{agent_id}' not found")
        self._repo.delete(AgentId(agent_id))


class AssignNextJob:
    def __init__(self, repo: AgentRepositoryPort, dispatcher: AgentDispatcherPort) -> None:
        self._repo = repo
        self._dispatcher = dispatcher

    def execute(self, agent_id: str) -> str | None:
        idle = self._repo.find_idle()
        for candidate in idle:
            if candidate.id.value == agent_id and candidate.state == AgentState.ONLINE:
                job_id = f"job-{candidate.id.value}-{time.time_ns()}"
                result = self._dispatcher.assign_job(candidate.id, job_id)
                if result:
                    self._repo.update(result)
                return job_id
        return None


class ReportJobProgress:
    def __init__(self, repo: AgentRepositoryPort) -> None:
        self._repo = repo

    def execute(self, agent_id: str, job_id: str, progress: float) -> None:
        agent = self._repo.find_by_id(AgentId(agent_id))
        if not agent:
            from kingsec.application.errors import AgentNotFoundError

            raise AgentNotFoundError(f"Agent '{agent_id}' not found")
        if agent.current_job_id != job_id:
            from kingsec.application.errors import JobNotFoundError

            raise JobNotFoundError(f"Job '{job_id}' not assigned to agent '{agent_id}'")


class CompleteJob:
    def __init__(self, repo: AgentRepositoryPort, dispatcher: AgentDispatcherPort) -> None:
        self._repo = repo
        self._dispatcher = dispatcher

    def execute(self, agent_id: str, job_id: str) -> None:
        agent = self._repo.find_by_id(AgentId(agent_id))
        if not agent:
            from kingsec.application.errors import AgentNotFoundError

            raise AgentNotFoundError(f"Agent '{agent_id}' not found")
        completed = Agent(
            id=agent.id,
            name=agent.name,
            platform=agent.platform,
            architecture=agent.architecture,
            version=agent.version,
            hostname=agent.hostname,
            state=AgentState.ONLINE,
            capability=agent.capability,
            api_key_hash=agent.api_key_hash,
            health=agent.health,
            statistics=AgentStatistics(
                total_jobs_assigned=agent.statistics.total_jobs_assigned + 1,
                total_jobs_completed=agent.statistics.total_jobs_completed + 1,
                total_jobs_failed=agent.statistics.total_jobs_failed,
                uptime_seconds=agent.statistics.uptime_seconds,
                last_heartbeat_at=agent.last_heartbeat_at,
            ),
            current_job_id=None,
            registered_at=agent.registered_at,
            last_heartbeat_at=agent.last_heartbeat_at,
            tags=agent.tags,
        )
        self._repo.update(completed)
        self._dispatcher.cancel_job(agent.id)


class FailJob:
    def __init__(self, repo: AgentRepositoryPort, dispatcher: AgentDispatcherPort) -> None:
        self._repo = repo
        self._dispatcher = dispatcher

    def execute(self, agent_id: str, job_id: str, error: str) -> None:
        agent = self._repo.find_by_id(AgentId(agent_id))
        if not agent:
            from kingsec.application.errors import AgentNotFoundError

            raise AgentNotFoundError(f"Agent '{agent_id}' not found")
        failed = Agent(
            id=agent.id,
            name=agent.name,
            platform=agent.platform,
            architecture=agent.architecture,
            version=agent.version,
            hostname=agent.hostname,
            state=AgentState.ONLINE,
            capability=agent.capability,
            api_key_hash=agent.api_key_hash,
            health=AgentHealth(
                cpu_usage_percent=agent.health.cpu_usage_percent,
                memory_usage_percent=agent.health.memory_usage_percent,
                disk_usage_percent=agent.health.disk_usage_percent,
                uptime_seconds=agent.health.uptime_seconds,
                error_message=error,
            ),
            statistics=AgentStatistics(
                total_jobs_assigned=agent.statistics.total_jobs_assigned + 1,
                total_jobs_completed=agent.statistics.total_jobs_completed,
                total_jobs_failed=agent.statistics.total_jobs_failed + 1,
                uptime_seconds=agent.statistics.uptime_seconds,
                last_heartbeat_at=agent.last_heartbeat_at,
            ),
            current_job_id=None,
            registered_at=agent.registered_at,
            last_heartbeat_at=agent.last_heartbeat_at,
            tags=agent.tags,
        )
        self._repo.update(failed)
        self._dispatcher.cancel_job(agent.id)
