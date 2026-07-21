from __future__ import annotations

from kingsec.domain.agent import (
    Agent,
    AgentArchitecture,
    AgentCapability,
    AgentId,
    AgentPlatform,
    AgentState,
)
from kingsec.infrastructure.agent.repository import InMemoryAgentRepository


class TestInMemoryAgentRepository:
    def setup_method(self) -> None:
        self.repo = InMemoryAgentRepository()
        self.agent = Agent(
            id=AgentId("a1"),
            name="Agent One",
            platform=AgentPlatform.LINUX,
            architecture=AgentArchitecture.AMD64,
            version="2.0.0",
            hostname="worker-1",
            state=AgentState.ONLINE,
            capability=AgentCapability(),
            api_key_hash="hash",
        )

    def test_register_and_find(self) -> None:
        self.repo.register(self.agent)
        found = self.repo.find_by_id(AgentId("a1"))
        assert found is not None
        assert found.name == "Agent One"

    def test_find_not_found(self) -> None:
        assert self.repo.find_by_id(AgentId("nonexistent")) is None

    def test_find_all(self) -> None:
        self.repo.register(self.agent)
        a2 = Agent(
            id=AgentId("a2"),
            name="Agent Two",
            platform=AgentPlatform.LINUX,
            architecture=AgentArchitecture.AMD64,
            version="1.0",
            hostname="w2",
            state=AgentState.ONLINE,
            capability=AgentCapability(),
            api_key_hash="h2",
        )
        self.repo.register(a2)
        assert len(self.repo.find_all()) == 2

    def test_update(self) -> None:
        self.repo.register(self.agent)
        updated = Agent(
            id=AgentId("a1"),
            name="Updated",
            platform=AgentPlatform.LINUX,
            architecture=AgentArchitecture.AMD64,
            version="2.0.0",
            hostname="worker-1",
            state=AgentState.BUSY,
            capability=AgentCapability(),
            api_key_hash="hash",
        )
        self.repo.update(updated)
        found = self.repo.find_by_id(AgentId("a1"))
        assert found is not None
        assert found.state == AgentState.BUSY
        assert found.name == "Updated"

    def test_delete(self) -> None:
        self.repo.register(self.agent)
        self.repo.delete(AgentId("a1"))
        assert self.repo.find_by_id(AgentId("a1")) is None

    def test_find_online(self) -> None:
        self.repo.register(self.agent)
        busy = Agent(
            id=AgentId("a2"),
            name="Busy",
            platform=AgentPlatform.LINUX,
            architecture=AgentArchitecture.AMD64,
            version="1.0",
            hostname="w2",
            state=AgentState.BUSY,
            capability=AgentCapability(),
            api_key_hash="h2",
        )
        self.repo.register(busy)
        online = self.repo.find_online()
        assert len(online) == 1
        assert online[0].id.value == "a1"

    def test_find_idle(self) -> None:
        self.repo.register(self.agent)
        busy = Agent(
            id=AgentId("a2"),
            name="Busy",
            platform=AgentPlatform.LINUX,
            architecture=AgentArchitecture.AMD64,
            version="1.0",
            hostname="w2",
            state=AgentState.ONLINE,
            capability=AgentCapability(),
            api_key_hash="h2",
            current_job_id="job-1",
        )
        self.repo.register(busy)
        idle = self.repo.find_idle()
        assert len(idle) == 1
        assert idle[0].id.value == "a1"
