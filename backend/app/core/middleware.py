import json
import logging
import uuid

from starlette.types import ASGIApp, Message, Receive, Scope, Send

from app.core.errors import NO_STORE, REQUEST_ID_HEADER, error_body

logger = logging.getLogger("scamshield")


class NoStoreMiddleware:
    """Adds ``Cache-Control: no-store`` to every response under /api/.

    Analysis responses can carry user content (evidence excerpts), so no cache may keep them.
    """

    def __init__(self, app: ASGIApp) -> None:
        self.app = app

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        if scope["type"] != "http" or not str(scope.get("path", "")).startswith("/api/"):
            await self.app(scope, receive, send)
            return

        async def send_no_store(message: Message) -> None:
            if message["type"] == "http.response.start":
                headers = [(k, v) for k, v in message["headers"] if k.lower() != b"cache-control"]
                headers.append((b"cache-control", NO_STORE.encode()))
                message["headers"] = headers
            await send(message)

        await self.app(scope, receive, send_no_store)


class CatchAllMiddleware:
    """Outermost layer: no exception escapes to the server.

    Starlette re-raises unhandled errors after answering, and the server would then
    log the traceback with the exception text, which can contain submitted content.
    This logs the exception type only and does not re-raise.
    """

    def __init__(self, app: ASGIApp) -> None:
        self.app = app

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        if scope["type"] != "http":
            await self.app(scope, receive, send)
            return

        started = False

        async def tracking_send(message: Message) -> None:
            nonlocal started
            if message["type"] == "http.response.start":
                started = True
            await send(message)

        try:
            await self.app(scope, receive, tracking_send)
        except Exception as exc:
            request_id = str(scope.get("state", {}).get("request_id") or uuid.uuid4())
            logger.error(
                "unhandled exception request_id=%s type=%s", request_id, type(exc).__name__
            )
            if started:
                return
            body = json.dumps(
                error_body("internal_error", "An unexpected error occurred.", request_id)
            ).encode()
            headers = [
                (b"content-type", b"application/json"),
                (b"content-length", str(len(body)).encode()),
                (REQUEST_ID_HEADER.lower().encode(), request_id.encode()),
            ]
            if str(scope.get("path", "")).startswith("/api/"):
                headers.append((b"cache-control", NO_STORE.encode()))
            await send({"type": "http.response.start", "status": 500, "headers": headers})
            await send({"type": "http.response.body", "body": body})
