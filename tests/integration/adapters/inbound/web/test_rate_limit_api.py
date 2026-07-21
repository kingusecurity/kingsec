from __future__ import annotations

import pytest
from fastapi import Depends, FastAPI
from fastapi.testclient import TestClient

from kingsec.adapters.inbound.web.error_handlers import register_error_handlers
from kingsec.adapters.inbound.web.rate_limit_deps import require_rate_limit
from kingsec.application.ports.outbound.clock_port import ClockPort
from kingsec.application.ports.outbound.lockout_repository import LockoutRepository
from kingsec.application.ports.outbound.rate_limiter import RateLimiterPort
from kingsec.application.use_cases.check_account_lockout import CheckAccountLockout
from kingsec.application.use_cases.check_rate_limit import CheckRateLimit
from kingsec.application.use_cases.record_failed_authentication import (
    RecordFailedAuthentication,
)
from kingsec.application.use_cases.record_successful_authentication import (
    RecordSuccessfulAuthentication,
)
from kingsec.application.use_cases.reset_failed_attempts import ResetFailedAttempts
from kingsec.bootstrap.application import Application
from kingsec.bootstrap.container import Container
from kingsec.domain.rate_limit import RateLimitGroup
from kingsec.infrastructure.config import Settings
from kingsec.infrastructure.rate_limit.in_memory_lockout_repository import (
    InMemoryLockoutRepository,
)
from kingsec.infrastructure.rate_limit.in_memory_rate_limiter import (
    InMemoryRateLimiter,
)
from kingsec.infrastructure.rate_limit.system_clock import SystemClock


@pytest.fixture
def app() -> FastAPI:
    container = Container()

    rate_limiter = InMemoryRateLimiter()
    clock: ClockPort = SystemClock()
    lockout_repo: LockoutRepository = InMemoryLockoutRepository()

    container.register_instance(RateLimiterPort, rate_limiter)
    container.register_instance(ClockPort, clock)
    container.register_instance(LockoutRepository, lockout_repo)

    container.register_factory(
        CheckRateLimit,
        lambda c: CheckRateLimit(c.resolve(RateLimiterPort)),
    )
    container.register_factory(
        RecordFailedAuthentication,
        lambda c: RecordFailedAuthentication(
            c.resolve(LockoutRepository),
            c.resolve(ClockPort),
        ),
    )
    container.register_factory(
        RecordSuccessfulAuthentication,
        lambda c: RecordSuccessfulAuthentication(c.resolve(LockoutRepository)),
    )
    container.register_factory(
        CheckAccountLockout,
        lambda c: CheckAccountLockout(
            c.resolve(LockoutRepository), c.resolve(ClockPort)
        ),
    )
    container.register_factory(
        ResetFailedAttempts,
        lambda c: ResetFailedAttempts(c.resolve(LockoutRepository)),
    )

    settings = Settings()
    application = Application(
        settings=settings,
        container=container,
        exception_handlers=None,
        logger=None,
        ensure_directories=False,
    )

    fastapi_app = FastAPI()
    fastapi_app.state.kingsec_app = application
    register_error_handlers(fastapi_app)

    @fastapi_app.get("/test")
    async def test_endpoint(
        _=Depends(require_rate_limit(RateLimitGroup.API)),
    ):
        return {"ok": True}

    @fastapi_app.post("/api/v1/auth/login")
    async def login_endpoint(
        _=Depends(require_rate_limit(RateLimitGroup.LOGIN)),
    ):
        return {"ok": True}

    return fastapi_app


class TestRateLimitAPI:
    def test_returns_headers_on_success(self, app: FastAPI) -> None:
        client = TestClient(app)
        resp = client.get("/test")
        assert resp.status_code == 200
        assert "X-RateLimit-Limit" in resp.headers
        assert "X-RateLimit-Remaining" in resp.headers
        assert "X-RateLimit-Reset" in resp.headers

    def test_rate_limits_after_exhaustion(self, app: FastAPI) -> None:
        client = TestClient(app)

        for i in range(5):
            resp = client.post("/api/v1/auth/login", json={})
            assert resp.status_code == 200, f"request {i+1} should succeed"

        resp = client.post("/api/v1/auth/login", json={})
        assert resp.status_code == 429
        data = resp.json()
        assert "error_code" in data
        assert "retry_after" in data

    def test_429_has_retry_after(self, app: FastAPI) -> None:
        client = TestClient(app)
        for _ in range(5):
            client.post("/api/v1/auth/login", json={})

        resp = client.post("/api/v1/auth/login", json={})
        assert resp.status_code == 429
        assert "Retry-After" in resp.headers
        retry_after = int(resp.headers["Retry-After"])
        assert retry_after > 0

    def test_different_endpoints_independent(self, app: FastAPI) -> None:
        client = TestClient(app)
        for _ in range(5):
            client.post("/api/v1/auth/login", json={})

        resp = client.get("/test")
        assert resp.status_code == 200
        assert int(resp.headers["X-RateLimit-Remaining"]) > 0

    def test_headers_present_on_429(self, app: FastAPI) -> None:
        client = TestClient(app)
        for _ in range(5):
            client.post("/api/v1/auth/login", json={})

        resp = client.post("/api/v1/auth/login", json={})
        assert resp.status_code == 429
        assert "X-RateLimit-Limit" in resp.headers
        assert "X-RateLimit-Remaining" in resp.headers
        assert "X-RateLimit-Reset" in resp.headers
        assert resp.headers["X-RateLimit-Remaining"] == "0"
