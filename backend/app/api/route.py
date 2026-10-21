"""Route class that runs the early request checks in the order the API promises.

Order after routing: Content-Type (415), body size (413), JSON syntax (422). Schema
validation (422) is done by FastAPI afterwards, and the rate limit (429) runs in the
handler once the request is known to be valid.
"""

import json
from collections.abc import Callable, Coroutine
from typing import Any

from fastapi import Request, Response
from fastapi.routing import APIRoute

from app.core.errors import ApiError

MAX_BODY_BYTES = 64 * 1024


def _is_json_content_type(header: str | None) -> bool:
    if not header:
        return False
    media_type, *params = (part.strip() for part in header.split(";"))
    if media_type.lower() != "application/json":
        return False
    for param in params:
        name, _, value = param.partition("=")
        if name.strip().lower() != "charset" or value.strip().strip('"').lower() != "utf-8":
            return False
    return True


def _too_large() -> ApiError:
    return ApiError(413)


async def _read_capped_body(request: Request) -> bytes:
    declared = request.headers.get("content-length")
    if declared is not None and declared.isdigit() and int(declared) > MAX_BODY_BYTES:
        raise _too_large()
    chunks: list[bytes] = []
    size = 0
    async for chunk in request.stream():
        size += len(chunk)
        if size > MAX_BODY_BYTES:
            raise _too_large()
        chunks.append(chunk)
    return b"".join(chunks)


def _malformed_json() -> ApiError:
    return ApiError(422, details=[{"field": None, "issue": "malformed_json"}])


def _check_json_syntax(body: bytes) -> None:
    try:
        json.loads(body.decode("utf-8"))
    except (UnicodeDecodeError, ValueError, RecursionError):
        raise _malformed_json() from None


class CheckedRoute(APIRoute):
    def get_route_handler(self) -> Callable[[Request], Coroutine[Any, Any, Response]]:
        original = super().get_route_handler()

        async def handler(request: Request) -> Response:
            if not _is_json_content_type(request.headers.get("content-type")):
                raise ApiError(415)
            body = await _read_capped_body(request)
            _check_json_syntax(body)

            consumed = False

            async def replay() -> dict[str, Any]:
                nonlocal consumed
                if consumed:
                    return {"type": "http.disconnect"}
                consumed = True
                return {"type": "http.request", "body": body, "more_body": False}

            return await original(Request(request.scope, replay))

        return handler
