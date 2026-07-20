from __future__ import annotations

from kingsec.domain.agent import (
    Agent,
    AgentArchitecture,
    AgentCapability,
    AgentHealth,
    AgentHeartbeat,
    AgentId,
    AgentPlatform,
    AgentRegistration,
    AgentState,
    AgentStatistics,
)


class TestAgentId:
    def test_create(self) -> None:
        aid = AgentId("agent-1")
        assert aid.value == "agent-1"
        assert str(aid) == "agent-1"


class TestAgentCapability:
    def test_defaults(self) -> None:
        c = AgentCapability()
        assert c.max_concurrent_jobs == 1

    def test_with_values(self) -> None:
        c = AgentCapability(max_concurrent_jobs=5, supported_scanners=("nmap", "gobuster"))
        assert c.max_concurrent_jobs == 5
        assert "nmap" in c.supported_scanners


class TestAgentHealth:
    def test_defaults(self) -> None:
        h = AgentHealth()
        assert h.cpu_usage_percent == 0.0

    def test_with_values(self) -> None:
        h = AgentHealth(cpu_usage_percent=45.5, memory_usage_percent=60.0, uptime_seconds=3600)
        assert h.cpu_usage_percent == 45.5
        assert h.uptime_seconds == 3600


class TestAgentRegistration:
    def test_create(self) -> None:
        reg = AgentRegistration(
            agent_id=AgentId("a1"),
            name="Agent One",
            platform=AgentPlatform.LINUX,
            architecture=AgentArchitecture.AMD64,
            version="2.0.0",
            hostname="worker-1",
            capability=AgentCapability(),
            api_key_hash="abc123",
        )
        assert reg.agent_id.value == "a1"
        assert reg.platform == AgentPlatform.LINUX


class TestAgentHeartbeat:
    def test_create(self) -> None:
        hb = AgentHeartbeat(
            agent_id=AgentId("a1"),
            state=AgentState.ONLINE,
            health=AgentHealth(),
            jobs_completed=5,
            jobs_failed=1,
        )
        assert hb.agent_id.value == "a1"
        assert hb.state == AgentState.ONLINE
        assert hb.jobs_completed == 5


class TestAgent:
    def test_create(self) -> None:
        a = Agent(
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
        assert a.id.value == "a1"
        assert a.state == AgentState.ONLINE

    def test_frozen(self) -> None:
        a = Agent(
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
        import pytest
        with pytest.raises(AttributeError):
            a.state = AgentState.BUSY  # type: ignore

    def test_statistics_defaults(self) -> None:
        s = AgentStatistics()
        assert s.total_jobs_assigned == 0
        assert s.total_jobs_completed == 0

    def test_statistics_with_values(self) -> None:
        s = AgentStatistics(total_jobs_assigned=10, total_jobs_completed=7, total_jobs_failed=3)
        assert s.total_jobs_assigned == 10
        assert s.total_jobs_completed == 7
        assert s.total_jobs_failed == 3


class TestEnums:
    def test_agent_platform(self) -> None:
        assert AgentPlatform.WINDOWS.value == "windows"
        assert AgentPlatform.LINUX.value == "linux"
        assert AgentPlatform.MACOS.value == "macos"

    def test_agent_architecture(self) -> None:
        assert AgentArchitecture.AMD64.value == "amd64"
        assert AgentArchitecture.ARM64.value == "arm64"

    def test_agent_state(self) -> None:
        assert AgentState.OFFLINE.value == "offline"
        assert AgentState.ONLINE.value == "online"
        assert AgentState.BUSY.value == "busy"
        assert AgentState.MAINTENANCE.value == "maintenance"
        assert AgentState.DISABLED.value == "disabled"
