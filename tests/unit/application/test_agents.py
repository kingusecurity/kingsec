from __future__ import annotations

import pytest

from kingsec.application.agent_service import AgentService
from kingsec.domain.agent import (
    AgentArchitecture,
    AgentCapability,
    AgentHealth,
    AgentHeartbeat,
    AgentId,
    AgentPlatform,
    AgentRegistration,
    AgentState,
)
from kingsec.infrastructure.agent.dispatcher import InMemoryAgentDispatcher
from kingsec.infrastructure.agent.repository import InMemoryAgentRepository


class TestRegisterAgent:
    def setup_method(self) -> None:
        self.repo = InMemoryAgentRepository()
        self.dispatcher = InMemoryAgentDispatcher()
        self.service = AgentService(self.repo, self.dispatcher)

    def _reg(self, agent_id: str = "agent-1") -> AgentRegistration:
        return AgentRegistration(
            agent_id=AgentId(agent_id),
            name="Test Agent",
            platform=AgentPlatform.LINUX,
            architecture=AgentArchitecture.AMD64,
            version="1.0.0",
            hostname="host-1",
            capability=AgentCapability(),
            api_key_hash="abc",
        )

    def test_register_success(self) -> None:
        agent = self.service.register(self._reg())
        assert agent.id.value == "agent-1"
        assert agent.state == AgentState.ONLINE

    def test_register_is_stored(self) -> None:
        self.service.register(self._reg())
        found = self.repo.find_by_id(AgentId("agent-1"))
        assert found is not None
        assert found.name == "Test Agent"


class TestUpdateHeartbeat:
    def setup_method(self) -> None:
        self.repo = InMemoryAgentRepository()
        self.dispatcher = InMemoryAgentDispatcher()
        self.service = AgentService(self.repo, self.dispatcher)
        reg = AgentRegistration(
            agent_id=AgentId("agent-1"),
            name="Test",
            platform=AgentPlatform.LINUX,
            architecture=AgentArchitecture.AMD64,
            version="1.0.0",
            hostname="h",
            capability=AgentCapability(),
            api_key_hash="",
        )
        self.service.register(reg)

    def test_heartbeat_updates_state(self) -> None:
        hb = AgentHeartbeat(
            agent_id=AgentId("agent-1"),
            state=AgentState.BUSY,
            health=AgentHealth(cpu_usage_percent=50.0),
            jobs_completed=3,
        )
        self.service.handle_heartbeat(hb)
        agent = self.repo.find_by_id(AgentId("agent-1"))
        assert agent is not None
        assert agent.state == AgentState.BUSY
        assert agent.health.cpu_usage_percent == 50.0
        assert agent.statistics.total_jobs_completed == 3

    def test_heartbeat_not_found(self) -> None:
        hb = AgentHeartbeat(
            agent_id=AgentId("nonexistent"),
            state=AgentState.ONLINE,
            health=AgentHealth(),
        )
        from kingsec.application.errors import AgentNotFoundError

        with pytest.raises(AgentNotFoundError):
            self.service.handle_heartbeat(hb)


class TestListGetAgents:
    def setup_method(self) -> None:
        self.repo = InMemoryAgentRepository()
        self.dispatcher = InMemoryAgentDispatcher()
        self.service = AgentService(self.repo, self.dispatcher)

    def test_list_empty(self) -> None:
        assert self.service.list_agents() == []

    def test_list_with_agents(self) -> None:
        reg = AgentRegistration(
            agent_id=AgentId("a1"),
            name="A1",
            platform=AgentPlatform.LINUX,
            architecture=AgentArchitecture.AMD64,
            version="1.0",
            hostname="h",
            capability=AgentCapability(),
            api_key_hash="",
        )
        self.service.register(reg)
        agents = self.service.list_agents()
        assert len(agents) == 1

    def test_get_agent_found(self) -> None:
        reg = AgentRegistration(
            agent_id=AgentId("a1"),
            name="A1",
            platform=AgentPlatform.LINUX,
            architecture=AgentArchitecture.AMD64,
            version="1.0",
            hostname="h",
            capability=AgentCapability(),
            api_key_hash="",
        )
        self.service.register(reg)
        agent = self.service.get_agent("a1")
        assert agent is not None
        assert agent.name == "A1"

    def test_get_agent_not_found(self) -> None:
        assert self.service.get_agent("nonexistent") is None


class TestDisableEnableAgent:
    def setup_method(self) -> None:
        self.repo = InMemoryAgentRepository()
        self.dispatcher = InMemoryAgentDispatcher()
        self.service = AgentService(self.repo, self.dispatcher)
        reg = AgentRegistration(
            agent_id=AgentId("a1"),
            name="A1",
            platform=AgentPlatform.LINUX,
            architecture=AgentArchitecture.AMD64,
            version="1.0",
            hostname="h",
            capability=AgentCapability(),
            api_key_hash="",
        )
        self.service.register(reg)

    def test_disable(self) -> None:
        agent = self.service.disable_agent("a1")
        assert agent.state == AgentState.DISABLED

    def test_enable(self) -> None:
        self.service.disable_agent("a1")
        agent = self.service.enable_agent("a1")
        assert agent.state == AgentState.ONLINE

    def test_disable_not_found(self) -> None:
        from kingsec.application.errors import AgentNotFoundError

        with pytest.raises(AgentNotFoundError):
            self.service.disable_agent("nonexistent")


class TestRemoveAgent:
    def setup_method(self) -> None:
        self.repo = InMemoryAgentRepository()
        self.dispatcher = InMemoryAgentDispatcher()
        self.service = AgentService(self.repo, self.dispatcher)
        reg = AgentRegistration(
            agent_id=AgentId("a1"),
            name="A1",
            platform=AgentPlatform.LINUX,
            architecture=AgentArchitecture.AMD64,
            version="1.0",
            hostname="h",
            capability=AgentCapability(),
            api_key_hash="",
        )
        self.service.register(reg)

    def test_remove(self) -> None:
        self.service.remove_agent("a1")
        assert self.service.get_agent("a1") is None

    def test_remove_not_found(self) -> None:
        from kingsec.application.errors import AgentNotFoundError

        with pytest.raises(AgentNotFoundError):
            self.service.remove_agent("nonexistent")


class TestAssignNextJob:
    def setup_method(self) -> None:
        self.repo = InMemoryAgentRepository()
        self.dispatcher = InMemoryAgentDispatcher()
        self.service = AgentService(self.repo, self.dispatcher)

    def test_no_idle_agents(self) -> None:
        job_id = self.service.assign_next_job("agent-1")
        assert job_id is None

    def test_assign_to_idle_agent(self) -> None:
        reg = AgentRegistration(
            agent_id=AgentId("a1"),
            name="A1",
            platform=AgentPlatform.LINUX,
            architecture=AgentArchitecture.AMD64,
            version="1.0",
            hostname="h",
            capability=AgentCapability(),
            api_key_hash="",
        )
        self.service.register(reg)
        job_id = self.service.assign_next_job("a1")
        assert job_id is not None
        assert job_id.startswith("job-")


class TestCompleteFailJob:
    def setup_method(self) -> None:
        self.repo = InMemoryAgentRepository()
        self.dispatcher = InMemoryAgentDispatcher()
        self.service = AgentService(self.repo, self.dispatcher)
        reg = AgentRegistration(
            agent_id=AgentId("a1"),
            name="A1",
            platform=AgentPlatform.LINUX,
            architecture=AgentArchitecture.AMD64,
            version="1.0",
            hostname="h",
            capability=AgentCapability(),
            api_key_hash="",
        )
        self.service.register(reg)

    def test_complete_job(self) -> None:
        job_id = self.service.assign_next_job("a1")
        assert job_id is not None
        self.service.complete_job("a1", job_id)
        agent = self.service.get_agent("a1")
        assert agent is not None
        assert agent.statistics.total_jobs_completed == 1

    def test_fail_job(self) -> None:
        job_id = self.service.assign_next_job("a1")
        assert job_id is not None
        self.service.fail_job("a1", job_id, "scan error")
        agent = self.service.get_agent("a1")
        assert agent is not None
        assert agent.statistics.total_jobs_failed == 1
        assert "scan error" in agent.health.error_message

    def test_complete_not_found(self) -> None:
        from kingsec.application.errors import AgentNotFoundError

        with pytest.raises(AgentNotFoundError):
            self.service.complete_job("nonexistent", "job-1")

    def test_report_progress(self) -> None:
        job_id = self.service.assign_next_job("a1")
        self.service.report_job_progress("a1", job_id, 50.0)

    def test_report_progress_not_found(self) -> None:
        from kingsec.application.errors import AgentNotFoundError

        with pytest.raises(AgentNotFoundError):
            self.service.report_job_progress("nonexistent", "job-1", 50.0)
