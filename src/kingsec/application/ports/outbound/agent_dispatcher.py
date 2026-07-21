from __future__ import annotations

from abc import ABC, abstractmethod

from kingsec.domain.agent import Agent, AgentId


class AgentDispatcherPort(ABC):
    @abstractmethod
    def assign_job(self, agent_id: AgentId, job_id: str) -> Agent | None: ...

    @abstractmethod
    def cancel_job(self, agent_id: AgentId) -> None: ...

    @abstractmethod
    def heartbeat(self, agent_id: AgentId) -> bool: ...

    @abstractmethod
    def register(self, agent: Agent) -> None: ...
