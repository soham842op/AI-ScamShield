from collections.abc import Sequence

from fastapi import Request

from app.core.config import Settings, get_settings
from app.core.errors import ApiError
from app.core.ratelimit import RateLimitDecision, Window, client_hash, resolve_client_ip
from app.core.services import Services, fail_closed

ANALYZE_SCOPE = "analyze"
FEEDBACK_SCOPE = "feedback"


def get_services(request: Request) -> Services:
    services: Services = request.app.state.services
    return services


def windows_for(scope: str, settings: Settings) -> Sequence[Window]:
    if scope == ANALYZE_SCOPE:
        return (
            Window("minute", 60, settings.rate_limit_analyze_per_minute),
            Window("day", 86400, settings.rate_limit_analyze_per_day),
        )
    return (Window("hour", 3600, settings.rate_limit_feedback_per_hour),)


async def enforce_rate_limit(request: Request, scope: str) -> RateLimitDecision:
    """Count the request and raise 429 when any window is over its limit.

    Database failures raise 503 (fail closed). Call only after the request is valid.
    """
    settings = get_settings()
    services = get_services(request)
    peer = request.client.host if request.client else None
    ip = resolve_client_ip(
        peer, request.headers.getlist("x-forwarded-for"), settings.trusted_proxy_hops
    )
    client = client_hash(services.client_id_key, ip, scope)
    with fail_closed():
        decision = await services.limiter.hit(scope, client, windows_for(scope, settings))
    if not decision.allowed:
        raise ApiError(429, headers=decision.headers())
    return decision
