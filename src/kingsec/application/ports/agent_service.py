from __future__ import annotations

from abc import ABC, abstractmethod

from kingsec.domain.agent import Agent, AgentHeartbeat, AgentId, AgentRegistration


class AgentServicePort(ABC):
    @abstractmethod
    def register(self, registration: AgentRegistration) -> Agent:
        ...

    @abstractmethod
    def handle_heartbeat(self, heartbeat: AgentHeartbeat) -> None:
        ...

    @abstractmethod
    def list_agents(self) -> list[Agent]:
        ...

    @abstractmethod
    def get_agent(self, agent_id: str) -> Agent | None:
        ...

    @abstractmethod
    def disable_agent(self, agent_id: str) -> Agent:
        ...

    @abstractmethod
    def enable_agent(self, agent_id: str) -> Agent:
        ...

    @abstractmethod
    def remove_agent(self, agent_id: str) -> None:
        ...

    @abstractmethod
    def assign_next_job(self, agent_id: str) -> str | None:
        ...

    @abstractmethod
    def report_job_progress(self, agent_id: str, job_id: str, progress: float) -> None:
        ...

    @abstractmethod
    def complete_job(self, agent_id: str, job_id: str) -> None:
        ...

    @abstractmethod
    def fail_job(self, agent_id: str, job_id: str, error: str) -> None:
        ...
