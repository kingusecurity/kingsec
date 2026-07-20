from __future__ import annotations

from abc import ABC, abstractmethod

from kingsec.domain.agent import Agent, AgentId


class AgentRepositoryPort(ABC):
    @abstractmethod
    def register(self, agent: Agent) -> None:
        ...

    @abstractmethod
    def update(self, agent: Agent) -> None:
        ...

    @abstractmethod
    def find_by_id(self, agent_id: AgentId) -> Agent | None:
        ...

    @abstractmethod
    def find_all(self) -> list[Agent]:
        ...

    @abstractmethod
    def delete(self, agent_id: AgentId) -> None:
        ...

    @abstractmethod
    def find_online(self) -> list[Agent]:
        ...

    @abstractmethod
    def find_idle(self) -> list[Agent]:
        ...
