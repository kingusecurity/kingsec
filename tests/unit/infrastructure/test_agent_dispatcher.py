from __future__ import annotations

from kingsec.domain.agent import (
    Agent,
    AgentArchitecture,
    AgentCapability,
    AgentId,
    AgentPlatform,
    AgentState,
)
from kingsec.infrastructure.agent.dispatcher import InMemoryAgentDispatcher


class TestInMemoryAgentDispatcher:
    def setup_method(self) -> None:
        self.dispatcher = InMemoryAgentDispatcher()
        self.agent = Agent(
            id=AgentId("a1"),
            name="Test",
            platform=AgentPlatform.LINUX,
            architecture=AgentArchitecture.AMD64,
            version="1.0",
            hostname="h",
            state=AgentState.ONLINE,
            capability=AgentCapability(),
            api_key_hash="",
        )

    def test_register(self) -> None:
        self.dispatcher.register(self.agent)
        assert self.dispatcher.heartbeat(AgentId("a1")) is True

    def test_heartbeat_unknown(self) -> None:
        assert self.dispatcher.heartbeat(AgentId("nonexistent")) is False

    def test_assign_job_returns_updated_agent(self) -> None:
        self.dispatcher.register(self.agent)
        result = self.dispatcher.assign_job(AgentId("a1"), "job-1")
        assert result is not None
        assert result.state == AgentState.BUSY
        assert result.current_job_id == "job-1"

    def test_assign_job_unknown_agent(self) -> None:
        result = self.dispatcher.assign_job(AgentId("nonexistent"), "job-1")
        assert result is None

    def test_cancel_job(self) -> None:
        self.dispatcher.register(self.agent)
        self.dispatcher.assign_job(AgentId("a1"), "job-1")
        self.dispatcher.cancel_job(AgentId("a1"))
