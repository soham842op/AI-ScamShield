import logging
import uuid
from collections.abc import Sequence
from typing import Any, cast

from fastapi import FastAPI, Request
from fastapi.exceptions import RequestValidationError
from fastapi.responses import JSONResponse
from starlette.exceptions import HTTPException as StarletteHTTPException
from starlette.types import ASGIApp, Message, Receive, Scope, Send

logger = logging.getLogger("scamshield")

REQUEST_ID_HEADER = "X-Request-ID"

_STATUS_CODES: dict[int, tuple[str, str]] = {
    404: ("not_found", "The requested resource was not found."),
    405: ("method_not_allowed", "This method is not allowed for the requested resource."),
    409: ("conflict", "The request conflicts with the current state."),
    413: ("payload_too_large", "The request is too large."),
    415: ("unsupported_media_type", "The request content type is not supported."),
    422: ("validation_error", "The request could not be validated."),
    429: ("rate_limited", "Too many requests. Please wait a moment and try again."),
    503: ("service_unavailable", "The service is temporarily unavailable. Please try again later."),
}

_VALIDATION_ISSUES: dict[str, str] = {
    "missing": "required",
    "extra_forbidden": "unknown_field",
    "string_too_short": "min_length",
    "string_too_long": "max_length",
    "json_invalid": "malformed_json",
    "int_parsing": "invalid_type",
    "string_type": "invalid_type",
    "bool_type": "invalid_type",
    "dict_type": "invalid_type",
    "model_attributes_type": "invalid_type",
    "uuid_type": "invalid_type",
    # Raised by the request schemas with PydanticCustomError; the type is the issue name.
    "invalid_type": "invalid_type",
    "min_length": "min_length",
    "max_length": "max_length",
    "whitespace_only": "whitespace_only",
    "nul_character": "nul_character",
    "invalid_unicode": "invalid_unicode",
}

NO_STORE = "no-store"


class RequestIdMiddleware:
    """Generates a server-side request id; any client-supplied id is ignored."""

    def __init__(self, app: ASGIApp) -> None:
        self.app = app

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        if scope["type"] != "http":
            await self.app(scope, receive, send)
            return

        request_id = str(uuid.uuid4())
        scope.setdefault("state", {})["request_id"] = request_id
        header_name = REQUEST_ID_HEADER.lower().encode()

        async def send_with_id(message: Message) -> None:
            if message["type"] == "http.response.start":
                headers = [(k, v) for k, v in message["headers"] if k.lower() != header_name]
                headers.append((header_name, request_id.encode()))
                message["headers"] = headers
            await send(message)

        await self.app(scope, receive, send_with_id)


def _request_id(request: Request) -> str:
    return str(getattr(request.state, "request_id", None) or uuid.uuid4())


def error_body(
    code: str, message: str, request_id: str, details: list[dict[str, Any]] | None = None
) -> dict[str, Any]:
    error: dict[str, Any] = {"code": code, "message": message, "request_id": request_id}
    if details:
        error["details"] = details
    return {"error": error}


class ApiError(Exception):
    """An application error that maps to the error envelope.

    ``message`` must be safe to show to users: no submitted values, no internals.
    """

    def __init__(
        self,
        status_code: int,
        *,
        code: str | None = None,
        message: str | None = None,
        details: list[dict[str, Any]] | None = None,
        headers: dict[str, str] | None = None,
    ) -> None:
        default_code, default_message = _STATUS_CODES.get(
            status_code, ("internal_error", "An unexpected error occurred.")
        )
        super().__init__(code or default_code)
        self.status_code = status_code
        self.code = code or default_code
        self.message = message or default_message
        self.details = details
        self.headers = dict(headers or {})


async def api_error_handler(request: Request, exc: Exception) -> JSONResponse:
    exc = cast(ApiError, exc)
    return JSONResponse(
        error_body(exc.code, exc.message, _request_id(request), exc.details),
        status_code=exc.status_code,
        headers=exc.headers,
    )


async def http_exception_handler(request: Request, exc: Exception) -> JSONResponse:
    exc = cast(StarletteHTTPException, exc)
    code, message = _STATUS_CODES.get(
        exc.status_code, ("internal_error", "An unexpected error occurred.")
    )
    headers: dict[str, str] = {}
    if exc.status_code in (429, 503):
        retry_after = (exc.headers or {}).get("Retry-After")
        headers["Retry-After"] = retry_after or "30"
    allow = (exc.headers or {}).get("Allow")
    if exc.status_code == 405 and allow:
        headers["Allow"] = allow
    return JSONResponse(
        error_body(code, message, _request_id(request)),
        status_code=exc.status_code,
        headers=headers,
    )


def validation_details(errors: Sequence[Any]) -> list[dict[str, Any]]:
    """Map Pydantic errors to contract details. Never copies input, ctx or url."""
    details: list[dict[str, Any]] = []
    for item in errors:
        error_type = str(item.get("type"))
        loc = [str(part) for part in item.get("loc", ())]
        if loc and loc[0] in ("body", "query", "path", "header", "cookie"):
            loc = loc[1:]
        field = ".".join(loc) or None
        # A syntax error's location is a character offset, not a field. An unknown field
        # name is client content, so it is never echoed.
        if error_type in ("json_invalid", "extra_forbidden"):
            field = None
        detail: dict[str, Any] = {
            "field": field,
            "issue": _VALIDATION_ISSUES.get(error_type, "invalid_value"),
        }
        limit = (item.get("ctx") or {}).get("limit")
        if detail["issue"] == "max_length" and isinstance(limit, int):
            detail["limit"] = limit
        details.append(detail)
    return details or [{"field": None, "issue": "invalid_value"}]


def validation_error(details: list[dict[str, Any]]) -> ApiError:
    # input_too_long is only for exceeding a maximum length.
    if all(d.get("issue") == "max_length" for d in details):
        return ApiError(
            422,
            code="input_too_long",
            message="The input is too long.",
            details=details,
        )
    return ApiError(422, details=details)


async def validation_exception_handler(request: Request, exc: Exception) -> JSONResponse:
    exc = cast(RequestValidationError, exc)
    return await api_error_handler(request, validation_error(validation_details(exc.errors())))


def _unhandled_headers(request: Request, request_id: str) -> dict[str, str]:
    # This response is built outside the middleware stack, so it sets its own headers.
    headers = {REQUEST_ID_HEADER: request_id}
    if request.url.path.startswith("/api/"):
        headers["Cache-Control"] = NO_STORE
    return headers


async def unhandled_exception_handler(request: Request, exc: Exception) -> JSONResponse:
    request_id = _request_id(request)
    logger.error("unhandled exception request_id=%s type=%s", request_id, type(exc).__name__)
    return JSONResponse(
        error_body("internal_error", "An unexpected error occurred.", request_id),
        status_code=500,
        headers=_unhandled_headers(request, request_id),
    )


def register_error_handlers(app: FastAPI) -> None:
    app.add_exception_handler(ApiError, api_error_handler)
    app.add_exception_handler(StarletteHTTPException, http_exception_handler)
    app.add_exception_handler(RequestValidationError, validation_exception_handler)
    app.add_exception_handler(Exception, unhandled_exception_handler)
    app.add_middleware(RequestIdMiddleware)
