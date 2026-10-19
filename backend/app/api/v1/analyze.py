import time
from typing import Any
from uuid import UUID

from fastapi import APIRouter, Request, Response

from app.api.limits import ANALYZE_SCOPE, enforce_rate_limit, get_services
from app.api.mapping import now_utc, to_record, to_response
from app.api.route import CheckedRoute
from app.core.errors import ApiError
from app.core.ratelimit import RateLimitDecision
from app.core.services import fail_closed
from app.pipeline.types import AnalysisResult
from app.pipeline.urls import InvalidUrlError, UnsupportedSchemeError, parse_submitted_url
from app.schemas.analysis import AnalysisResponse, MessageAnalysisRequest, UrlAnalysisRequest
from app.schemas.errors import ErrorEnvelope

router = APIRouter(route_class=CheckedRoute)

_ERROR_RESPONSES: dict[int | str, dict[str, Any]] = {
    code: {"model": ErrorEnvelope, "description": text}
    for code, text in {
        413: "Request body larger than 64 KiB.",
        415: "Content-Type is not application/json.",
        422: "Malformed JSON or a field failed validation.",
        429: "Rate limit exceeded.",
        503: "The service is temporarily unavailable.",
    }.items()
}


async def _finish(
    request: Request,
    response: Response,
    result: AnalysisResult,
    started: float,
    decision: RateLimitDecision,
) -> AnalysisResponse:
    """Store the record, then build the response, so a 200 always implies a stored record."""
    request_id = UUID(request.state.request_id)
    created_at = now_utc()
    latency_ms = int((time.perf_counter() - started) * 1000)
    with fail_closed():
        await get_services(request).persistence.save_analysis(
            to_record(result, request_id, created_at, latency_ms)
        )
    response.headers.update(decision.headers())
    return to_response(result, request_id, created_at, latency_ms)


@router.post("/analyze/message", response_model=AnalysisResponse, responses=_ERROR_RESPONSES)
async def analyze_message_endpoint(
    payload: MessageAnalysisRequest, request: Request, response: Response
) -> AnalysisResponse:
    started = time.perf_counter()
    decision = await enforce_rate_limit(request, ANALYZE_SCOPE)
    services = get_services(request)
    try:
        result = await services.pipeline.analyze_message(
            payload.text, payload.channel, provider=services.provider
        )
        return await _finish(request, response, result, started, decision)
    except ApiError as exc:
        exc.headers = {**decision.headers(), **exc.headers}
        raise


@router.post("/analyze/url", response_model=AnalysisResponse, responses=_ERROR_RESPONSES)
async def analyze_url_endpoint(
    payload: UrlAnalysisRequest, request: Request, response: Response
) -> AnalysisResponse:
    started = time.perf_counter()
    # Parsing is pure and runs before the rate limit, so an invalid URL uses no quota.
    try:
        submitted = parse_submitted_url(payload.url)
    except InvalidUrlError:
        raise ApiError(
            422,
            code="invalid_url",
            message="The link could not be read as a valid web address.",
            details=[{"field": "url", "issue": "invalid_url"}],
        ) from None
    except UnsupportedSchemeError:
        raise ApiError(
            422,
            code="unsupported_url_scheme",
            message="Only http and https links can be analyzed.",
            details=[{"field": "url", "issue": "unsupported_scheme"}],
        ) from None
    decision = await enforce_rate_limit(request, ANALYZE_SCOPE)
    services = get_services(request)
    try:
        result = await services.pipeline.analyze_url(
            submitted, len(payload.url), provider=services.provider
        )
        return await _finish(request, response, result, started, decision)
    except ApiError as exc:
        exc.headers = {**decision.headers(), **exc.headers}
        raise
