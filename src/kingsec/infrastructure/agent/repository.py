from __future__ import annotations

from kingsec.application.ports.outbound import AgentRepositoryPort
from kingsec.domain.agent import Agent, AgentHealth, AgentId, AgentState, AgentStatistics


class InMemoryAgentRepository(AgentRepositoryPort):
    def __init__(self) -> None:
        self._agents: dict[str, Agent] = {}

    def register(self, agent: Agent) -> None:
        self._agents[agent.id.value] = agent

    def update(self, agent: Agent) -> None:
        self._agents[agent.id.value] = agent

    def find_by_id(self, agent_id: AgentId) -> Agent | None:
        return self._agents.get(agent_id.value)

    def find_all(self) -> list[Agent]:
        return list(self._agents.values())

    def delete(self, agent_id: AgentId) -> None:
        self._agents.pop(agent_id.value, None)

    def find_online(self) -> list[Agent]:
        return [a for a in self._agents.values() if a.state == AgentState.ONLINE]

    def find_idle(self) -> list[Agent]:
        return [
            a for a in self._agents.values()
            if a.state == AgentState.ONLINE and a.current_job_id is None
        ]


class SQLAlchemyAgentRepository(AgentRepositoryPort):
    def __init__(self, session_factory) -> None:
        self._session_factory = session_factory

    def register(self, agent: Agent) -> None:
        from sqlalchemy import text
        with self._session_factory() as session:
            session.execute(
                text("""
                    INSERT INTO agents (id, name, platform, architecture, version, hostname,
                        state, api_key_hash, registered_at, last_heartbeat_at)
                    VALUES (:id, :name, :platform, :architecture, :version, :hostname,
                        :state, :api_key_hash, :registered_at, :last_heartbeat_at)
                """),
                {
                    "id": agent.id.value,
                    "name": agent.name,
                    "platform": agent.platform.value,
                    "architecture": agent.architecture.value,
                    "version": agent.version,
                    "hostname": agent.hostname,
                    "state": agent.state.value,
                    "api_key_hash": agent.api_key_hash,
                    "registered_at": agent.registered_at,
                    "last_heartbeat_at": agent.last_heartbeat_at,
                },
            )
            session.commit()

    def update(self, agent: Agent) -> None:
        from sqlalchemy import text
        with self._session_factory() as session:
            session.execute(
                text("""
                    UPDATE agents SET name=:name, state=:state, version=:version,
                        hostname=:hostname, last_heartbeat_at=:last_heartbeat_at,
                        current_job_id=:current_job_id
                    WHERE id=:id
                """),
                {
                    "id": agent.id.value,
                    "name": agent.name,
                    "state": agent.state.value,
                    "version": agent.version,
                    "hostname": agent.hostname,
                    "last_heartbeat_at": agent.last_heartbeat_at,
                    "current_job_id": agent.current_job_id,
                },
            )
            session.commit()

    def find_by_id(self, agent_id: AgentId) -> Agent | None:
        from sqlalchemy import text
        with self._session_factory() as session:
            row = session.execute(
                text("SELECT * FROM agents WHERE id = :id"), {"id": agent_id.value}
            ).fetchone()
            if not row:
                return None
            return self._row_to_agent(row._mapping)

    def find_all(self) -> list[Agent]:
        from sqlalchemy import text
        with self._session_factory() as session:
            rows = session.execute(text("SELECT * FROM agents")).fetchall()
            return [self._row_to_agent(r._mapping) for r in rows]

    def delete(self, agent_id: AgentId) -> None:
        from sqlalchemy import text
        with self._session_factory() as session:
            session.execute(text("DELETE FROM agents WHERE id = :id"), {"id": agent_id.value})
            session.commit()

    def find_online(self) -> list[Agent]:
        from sqlalchemy import text
        with self._session_factory() as session:
            rows = session.execute(
                text("SELECT * FROM agents WHERE state = 'online'")
            ).fetchall()
            return [self._row_to_agent(r._mapping) for r in rows]

    def find_idle(self) -> list[Agent]:
        from sqlalchemy import text
        with self._session_factory() as session:
            rows = session.execute(
                text("SELECT * FROM agents WHERE state = 'online' AND current_job_id IS NULL")
            ).fetchall()
            return [self._row_to_agent(r._mapping) for r in rows]

    def _row_to_agent(self, row) -> Agent:
        from kingsec.domain.agent import AgentArchitecture, AgentCapability, AgentHealth, AgentPlatform, AgentState, AgentStatistics
        return Agent(
            id=AgentId(row["id"]),
            name=row.get("name", ""),
            platform=AgentPlatform(row.get("platform", "linux")),
            architecture=AgentArchitecture(row.get("architecture", "amd64")),
            version=row.get("version", ""),
            hostname=row.get("hostname", ""),
            state=AgentState(row.get("state", AgentState.OFFLINE.value)),
            capability=AgentCapability(),
            api_key_hash=row.get("api_key_hash", ""),
            health=AgentHealth(),
            statistics=AgentStatistics(),
            current_job_id=row.get("current_job_id"),
            registered_at=row.get("registered_at", ""),
            last_heartbeat_at=row.get("last_heartbeat_at", ""),
        )
