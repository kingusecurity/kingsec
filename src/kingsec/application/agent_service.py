from __future__ import annotations

from kingsec.application.ports.agent_service import AgentServicePort
from kingsec.application.ports.outbound import AgentDispatcherPort, AgentRepositoryPort
from kingsec.application.use_cases.agents import (
    AssignNextJob,
    CompleteJob,
    DisableAgent,
    EnableAgent,
    FailJob,
    GetAgent,
    ListAgents,
    RegisterAgent,
    RemoveAgent,
    ReportJobProgress,
    UpdateHeartbeat,
)
from kingsec.domain.agent import Agent, AgentHeartbeat, AgentRegistration


class AgentService(AgentServicePort):
    def __init__(self, repo: AgentRepositoryPort, dispatcher: AgentDispatcherPort) -> None:
        self._register_uc = RegisterAgent(repo, dispatcher)
        self._heartbeat_uc = UpdateHeartbeat(repo)
        self._list_uc = ListAgents(repo)
        self._get_uc = GetAgent(repo)
        self._disable_uc = DisableAgent(repo)
        self._enable_uc = EnableAgent(repo)
        self._remove_uc = RemoveAgent(repo)
        self._assign_next_uc = AssignNextJob(repo, dispatcher)
        self._progress_uc = ReportJobProgress(repo)
        self._complete_uc = CompleteJob(repo, dispatcher)
        self._fail_uc = FailJob(repo, dispatcher)

    def register(self, registration: AgentRegistration) -> Agent:
        return self._register_uc.execute(registration)

    def handle_heartbeat(self, heartbeat: AgentHeartbeat) -> None:
        self._heartbeat_uc.execute(heartbeat)

    def list_agents(self) -> list[Agent]:
        return self._list_uc.execute()

    def get_agent(self, agent_id: str) -> Agent | None:
        return self._get_uc.execute(agent_id)

    def disable_agent(self, agent_id: str) -> Agent:
        return self._disable_uc.execute(agent_id)

    def enable_agent(self, agent_id: str) -> Agent:
        return self._enable_uc.execute(agent_id)

    def remove_agent(self, agent_id: str) -> None:
        self._remove_uc.execute(agent_id)

    def assign_next_job(self, agent_id: str) -> str | None:
        return self._assign_next_uc.execute(agent_id)

    def report_job_progress(self, agent_id: str, job_id: str, progress: float) -> None:
        self._progress_uc.execute(agent_id, job_id, progress)

    def complete_job(self, agent_id: str, job_id: str) -> None:
        self._complete_uc.execute(agent_id, job_id)

    def fail_job(self, agent_id: str, job_id: str, error: str) -> None:
        self._fail_uc.execute(agent_id, job_id, error)
