from typing import Any

from fastapi import APIRouter, Request, Response

from app.api.limits import FEEDBACK_SCOPE, enforce_rate_limit, get_services
from app.api.mapping import utc_millis
from app.api.route import CheckedRoute
from app.core.errors import ApiError
from app.core.services import fail_closed
from app.db.repository import FeedbackOutcome
from app.schemas.errors import ErrorEnvelope
from app.schemas.feedback import FeedbackRequest, FeedbackResponse

router = APIRouter(route_class=CheckedRoute)

_ERROR_RESPONSES: dict[int | str, dict[str, Any]] = {
    code: {"model": ErrorEnvelope, "description": text}
    for code, text in {
        404: "No analysis with this request_id, or it has expired.",
        409: "Feedback was already submitted for this request_id.",
        413: "Request body larger than 64 KiB.",
        415: "Content-Type is not application/json.",
        422: "Malformed JSON or a field failed validation.",
        429: "Rate limit exceeded.",
        503: "The service is temporarily unavailable.",
    }.items()
}


@router.post(
    "/feedback", status_code=201, response_model=FeedbackResponse, responses=_ERROR_RESPONSES
)
async def feedback_endpoint(
    payload: FeedbackRequest, request: Request, response: Response
) -> FeedbackResponse:
    decision = await enforce_rate_limit(request, FEEDBACK_SCOPE)
    headers = decision.headers()
    try:
        with fail_closed():
            outcome = await get_services(request).persistence.save_feedback(
                payload.request_id, payload.helpful, payload.verdict
            )
    except ApiError as exc:
        exc.headers = {**headers, **exc.headers}
        raise
    if outcome.outcome is FeedbackOutcome.UNKNOWN_REQUEST:
        raise ApiError(404, headers=headers)
    if outcome.outcome is FeedbackOutcome.DUPLICATE:
        raise ApiError(409, headers=headers)
    if outcome.feedback_id is None or outcome.created_at is None:
        raise RuntimeError("feedback result is incomplete")
    response.headers.update(headers)
    return FeedbackResponse(
        feedback_id=outcome.feedback_id, received_at=utc_millis(outcome.created_at)
    )
