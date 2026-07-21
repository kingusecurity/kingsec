from __future__ import annotations

from kingsec.application.ports.outbound import AgentDispatcherPort
from kingsec.domain.agent import Agent, AgentId


class InMemoryAgentDispatcher(AgentDispatcherPort):
    """Polling-based dispatcher — no RabbitMQ, Kafka, or Redis.

    Agents poll for jobs. The dispatcher tracks assignment state in-memory.
    """

    def __init__(self) -> None:
        self._assignments: dict[str, str] = {}
        self._agents: dict[str, Agent] = {}

    def assign_job(self, agent_id: AgentId, job_id: str) -> Agent | None:
        self._assignments[agent_id.value] = job_id
        agent = self._agents.get(agent_id.value)
        if agent:
            from kingsec.domain.agent import AgentState

            updated = Agent(
                id=agent.id,
                name=agent.name,
                platform=agent.platform,
                architecture=agent.architecture,
                version=agent.version,
                hostname=agent.hostname,
                state=AgentState.BUSY,
                capability=agent.capability,
                api_key_hash=agent.api_key_hash,
                health=agent.health,
                statistics=agent.statistics,
                current_job_id=job_id,
                registered_at=agent.registered_at,
                last_heartbeat_at=agent.last_heartbeat_at,
                tags=agent.tags,
            )
            self._agents[agent_id.value] = updated
            return updated
        return None

    def cancel_job(self, agent_id: AgentId) -> None:
        self._assignments.pop(agent_id.value, None)

    def heartbeat(self, agent_id: AgentId) -> bool:
        return agent_id.value in self._agents

    def register(self, agent: Agent) -> None:
        self._agents[agent.id.value] = agent
