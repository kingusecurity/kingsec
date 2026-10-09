"""Profile-route wiring and target-boundary validation."""

from __future__ import annotations

from typing import Any

from fastapi import FastAPI
from fastapi.testclient import TestClient

from kingsec.adapters.inbound.web.profiles import create_profiles_router
from kingsec.application.assessment_profiles import ExecutionPlanner


class _ConfiguredPlanner:
    """Small seam fake proving the route resolves the configured planner."""

    def __init__(self) -> None:
        self.list_called = False

    def list_profiles(self) -> tuple[str, ...]:
        self.list_called = True
        return ("configured-profile",)

    def profile_to_dict(self, profile: str) -> dict[str, Any]:
        return {"id": profile, "name": "Configured profile"}


def _client(planner: object) -> TestClient:
    app = FastAPI()

    class _StubApplication:
        def resolve(self, service_type: type) -> object:
            assert service_type is ExecutionPlanner
            return planner

    app.state.kingsec_app = _StubApplication()  # type: ignore[attr-defined]
    app.include_router(create_profiles_router(get_current_user=lambda: object()))
    return TestClient(app)


def test_list_profiles_resolves_the_configured_execution_planner() -> None:
    planner = _ConfiguredPlanner()

    response = _client(planner).get("/profiles")

    assert response.status_code == 200
    assert response.json() == [{"id": "configured-profile", "name": "Configured profile"}]
    assert planner.list_called is True


def test_plan_rejects_a_malformed_target_before_planning() -> None:
    response = _client(ExecutionPlanner()).post(
        "/profiles/domain-enumeration/plan",
        json={"target": "localhost", "target_type": "domain"},
    )

    assert response.status_code == 422
    assert response.json()["detail"] == "domain must contain at least two DNS labels"
