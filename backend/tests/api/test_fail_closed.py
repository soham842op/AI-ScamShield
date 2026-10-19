"""A database failure at the limiter or at persistence gives 503 with Retry-After 30."""

import logging
from collections.abc import Callable

import psycopg
import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient
from httpx import Response
from sqlalchemy.exc import OperationalError, SQLAlchemyError
from sqlalchemy.exc import TimeoutError as PoolTimeoutError

from app.core.ratelimit import InMemoryRateLimiter
from tests.api.fakes import FakePersistence, RaisingLimiter

MESSAGE = "/api/v1/analyze/message"
URL = "/api/v1/analyze/url"
FEEDBACK = "/api/v1/feedback"
CANARY = "db-detail-in-error-text"

REQUESTS = [
    (MESSAGE, {"text": "hello"}),
    (URL, {"url": "example.com"}),
    (FEEDBACK, {"request_id": "3f2b8c1e-7a4d-4e61-9b0a-5d2c6f8e1a90", "helpful": True}),
]


def _errors() -> list[Exception]:
    return [
        SQLAlchemyError(CANARY),
        PoolTimeoutError(CANARY),
        OperationalError("stmt", None, Exception(CANARY)),
        psycopg.OperationalError(CANARY),
        psycopg.errors.AdminShutdown(CANARY),
    ]


def _assert_503(response: Response, caplog: pytest.LogCaptureFixture) -> None:
    assert response.status_code == 503
    assert response.headers["Retry-After"] == "30"
    error = response.json()["error"]
    assert error["code"] == "service_unavailable"
    assert error["request_id"] == response.headers["X-Request-ID"]
    assert "details" not in error
    assert CANARY not in response.text
    assert CANARY not in caplog.text


@pytest.mark.parametrize(("path", "body"), REQUESTS)
@pytest.mark.parametrize("error", _errors(), ids=lambda e: type(e).__name__)
def test_limiter_failure(
    make_app: Callable[..., FastAPI],
    caplog: pytest.LogCaptureFixture,
    path: str,
    body: dict[str, object],
    error: Exception,
) -> None:
    store = FakePersistence()
    app = make_app("production", limiter=RaisingLimiter(error), persistence=store)
    client = TestClient(app, raise_server_exceptions=False)
    with caplog.at_level(logging.DEBUG):
        _assert_503(client.post(path, json=body), caplog)
    assert store.records == []


@pytest.mark.parametrize(("path", "body"), REQUESTS)
@pytest.mark.parametrize("error", _errors(), ids=lambda e: type(e).__name__)
def test_persistence_failure(
    make_app: Callable[..., FastAPI],
    caplog: pytest.LogCaptureFixture,
    path: str,
    body: dict[str, object],
    error: Exception,
) -> None:
    store = FakePersistence()
    store.error = error
    app = make_app("production", limiter=InMemoryRateLimiter(), persistence=store)
    client = TestClient(app, raise_server_exceptions=False)
    with caplog.at_level(logging.DEBUG):
        _assert_503(client.post(path, json=body), caplog)


def test_503_logs_exception_type_only(
    make_app: Callable[..., FastAPI], caplog: pytest.LogCaptureFixture
) -> None:
    app = make_app(
        "production",
        limiter=RaisingLimiter(psycopg.OperationalError(CANARY)),
        persistence=FakePersistence(),
    )
    with caplog.at_level(logging.DEBUG):
        TestClient(app, raise_server_exceptions=False).post(MESSAGE, json={"text": "hello"})
    assert "OperationalError" in caplog.text


def test_unexpected_error_is_500_not_503(
    make_app: Callable[..., FastAPI], caplog: pytest.LogCaptureFixture
) -> None:
    store = FakePersistence()
    store.error = RuntimeError(CANARY)
    app = make_app("production", limiter=InMemoryRateLimiter(), persistence=store)
    response = TestClient(app, raise_server_exceptions=False).post(MESSAGE, json={"text": "hello"})
    assert response.status_code == 500
    assert response.json()["error"]["code"] == "internal_error"
    assert CANARY not in response.text
    assert response.headers["Cache-Control"] == "no-store"
