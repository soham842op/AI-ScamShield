import logging
from collections.abc import Callable

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient

from app.core.ratelimit import InMemoryRateLimiter
from app.core.services import database_engine
from tests.api.fakes import FakePersistence

MESSAGE = "/api/v1/analyze/message"
CANARY = "canary-secret"


def _boom_app(make_app: Callable[..., FastAPI]) -> FastAPI:
    app = make_app("production")

    @app.get("/api/_test/boom")
    async def api_boom() -> None:
        raise ValueError(CANARY)

    @app.get("/_test/boom")
    async def boom() -> None:
        raise ValueError(CANARY)

    return app


@pytest.mark.parametrize("path", ["/api/_test/boom", "/_test/boom"])
def test_unhandled_error_is_enveloped_and_not_logged(
    make_app: Callable[..., FastAPI], caplog: pytest.LogCaptureFixture, path: str
) -> None:
    # raise_server_exceptions=True: the test client must see no exception either.
    client = TestClient(_boom_app(make_app), raise_server_exceptions=True)
    with caplog.at_level(logging.DEBUG):
        logging.getLogger("uvicorn.error").setLevel(logging.DEBUG)
        response = client.get(path)
    assert response.status_code == 500
    error = response.json()["error"]
    assert error["code"] == "internal_error"
    assert error["request_id"] == response.headers["X-Request-ID"]
    assert CANARY not in response.text
    assert (response.headers.get("Cache-Control") == "no-store") == path.startswith("/api/")
    assert CANARY not in caplog.text
    for record in caplog.records:
        assert CANARY not in record.getMessage()
        assert record.exc_info is None
        assert CANARY not in str(record.args)
    assert "ValueError" in caplog.text


def test_405_has_allow_header(api_client: TestClient) -> None:
    response = api_client.get(MESSAGE)
    assert response.status_code == 405
    assert response.headers["Allow"] == "POST"
    assert response.json()["error"]["code"] == "method_not_allowed"


@pytest.mark.parametrize("path", [MESSAGE + "/", "/api/v1/feedback/", "/healthz/"])
def test_trailing_slash_is_404_not_redirect(api_client: TestClient, path: str) -> None:
    response = api_client.post(path, json={"text": "hello"}, follow_redirects=False)
    assert response.status_code in (404, 405)
    assert "Location" not in response.headers
    assert response.json()["error"]["code"] in ("not_found", "method_not_allowed")


def test_missing_database_url_is_503_not_500(
    make_app: Callable[..., FastAPI], monkeypatch: pytest.MonkeyPatch
) -> None:
    # Development may start without a database; requests then fail closed.
    monkeypatch.setenv("DATABASE_URL", "")
    app = make_app("development")
    response = TestClient(app, raise_server_exceptions=False).post(MESSAGE, json={"text": "hello"})
    assert response.status_code == 503
    assert response.headers["Retry-After"] == "30"
    assert response.json()["error"]["code"] == "service_unavailable"


def test_missing_database_url_is_503_at_persistence(
    make_app: Callable[..., FastAPI], monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setenv("DATABASE_URL", "")
    app = make_app("development", limiter=InMemoryRateLimiter())
    response = TestClient(app, raise_server_exceptions=False).post(MESSAGE, json={"text": "hello"})
    assert response.status_code == 503


def test_database_engine_wrapper_raises_sqlalchemy_error(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    from sqlalchemy.exc import SQLAlchemyError

    from app.core.config import get_settings

    monkeypatch.setenv("DATABASE_URL", "")
    get_settings.cache_clear()
    with pytest.raises(SQLAlchemyError):
        database_engine()


def test_readyz_503_has_retry_after(
    make_app: Callable[..., FastAPI], monkeypatch: pytest.MonkeyPatch
) -> None:
    from app import health

    async def down() -> bool:
        return False

    monkeypatch.setattr(health, "check_database", down)
    store = FakePersistence()
    app = make_app("production", limiter=InMemoryRateLimiter(), persistence=store)
    assert TestClient(app).get("/readyz").headers["Retry-After"] == "30"
