from __future__ import annotations

from collections.abc import Callable
from typing import TYPE_CHECKING, Any

from fastapi import Depends, Request, Response

from kingsec.application.use_cases.check_rate_limit import CheckRateLimit
from kingsec.application.use_cases.rate_limit_dto import CheckRateLimitRequest
from kingsec.domain.rate_limit import (
    RateLimitGroup,
    RateLimitKeyType,
    RateLimitPolicy,
)

if TYPE_CHECKING:
    from kingsec.bootstrap.application import Application

from .auth import bearer_scheme, get_current_api_key, get_current_user
from .dependencies import get_application

# Policies that are actually attached to at least one route.
# Unused policies have been removed — a false claim is worse than no claim.
DEFAULT_POLICIES: dict[RateLimitGroup, tuple[int, int, RateLimitKeyType]] = {
    RateLimitGroup.LOGIN: (5, 900, RateLimitKeyType.IP_USER),
    RateLimitGroup.API: (1000, 3600, RateLimitKeyType.USER),
    RateLimitGroup.REFRESH_TOKEN: (30, 3600, RateLimitKeyType.USER),
    RateLimitGroup.PASSWORD_CHANGE: (10, 3600, RateLimitKeyType.IP_USER),
    RateLimitGroup.MFA_VERIFY: (10, 600, RateLimitKeyType.IP_USER),
}


async def _resolve_identifier(
    request: Request,
    policy: RateLimitPolicy,
    app: Application,
) -> str:
    client_ip = request.client.host if request.client else "unknown"

    if policy.key_type == RateLimitKeyType.IP:
        return f"ip:{client_ip}"
    elif policy.key_type == RateLimitKeyType.ENDPOINT:
        return f"endpoint:{request.url.path}"
    elif policy.key_type == RateLimitKeyType.API_KEY:
        try:
            api_key = await get_current_api_key(request)
            key_id = api_key.key_id if hasattr(api_key, "key_id") else str(id(api_key))
            return f"apikey:{key_id}"
        except Exception:
            return f"ip:{client_ip}"
    elif policy.key_type == RateLimitKeyType.USER:
        try:
            creds = await bearer_scheme(request)
            user = await get_current_user(creds)
            return f"user:{user.user_id if hasattr(user, 'user_id') else str(id(user))}"
        except Exception:
            return f"ip:{client_ip}"
    elif policy.key_type == RateLimitKeyType.IP_USER:
        try:
            creds = await bearer_scheme(request)
            user = await get_current_user(creds)
            uid = user.user_id if hasattr(user, "user_id") else str(id(user))
            return f"ip_user:{client_ip}:{uid}"
        except Exception:
            return f"ip:{client_ip}"

    raise ValueError(f"unhandled rate-limit key type: {policy.key_type}")


def require_rate_limit(group: RateLimitGroup) -> Callable[..., Any]:
    max_reqs, window_secs, key_type = DEFAULT_POLICIES[group]

    async def dependency(
        request: Request,
        response: Response,
        app: Application = Depends(get_application),
    ) -> None:
        policy = RateLimitPolicy(
            group=group,
            max_requests=max_reqs,
            window_seconds=window_secs,
            key_type=key_type,
        )

        identifier = await _resolve_identifier(request, policy, app)

        check_rate_limit: CheckRateLimit = app.resolve(CheckRateLimit)
        req = CheckRateLimitRequest(key=identifier, policy=policy)

        result = check_rate_limit.execute(req)

        response.headers["X-RateLimit-Limit"] = str(result.limit)
        response.headers["X-RateLimit-Remaining"] = str(result.remaining)
        response.headers["X-RateLimit-Reset"] = str(result.reset_seconds)

    return dependency
