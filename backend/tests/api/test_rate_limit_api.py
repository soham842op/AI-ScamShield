from collections.abc import Callable
from datetime import UTC, datetime

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient

from app.core.ratelimit import InMemoryRateLimiter
from tests.api.fakes import FakePersistence

MESSAGE = "/api/v1/analyze/message"
URL = "/api/v1/analyze/url"
FEEDBACK = "/api/v1/feedback"
RL = ("RateLimit-Limit", "RateLimit-Remaining", "RateLimit-Reset")
# 12:00:30 UTC: 30 seconds left in the minute window.
NOW = datetime(2026, 10, 19, 12, 0, 30, tzinfo=UTC)


@pytest.fixture
def clocked(
    make_app: Callable[..., FastAPI], store: FakePersistence
) -> tuple[TestClient, InMemoryRateLimiter]:
    limiter = InMemoryRateLimiter(clock=lambda: NOW)
    app = make_app("production", limiter=limiter, persistence=store)
    return TestClient(app, raise_server_exceptions=False), limiter


def test_headers_on_success(clocked: tuple[TestClient, InMemoryRateLimiter]) -> None:
    client, _ = clocked
    response = client.post(MESSAGE, json={"text": "hello"})
    assert response.status_code == 200
    assert response.headers["RateLimit-Limit"] == "10"
    assert response.headers["RateLimit-Remaining"] == "9"
    assert response.headers["RateLimit-Reset"] == "30"
    assert "Retry-After" not in response.headers


def test_429_headers_and_envelope(clocked: tuple[TestClient, InMemoryRateLimiter]) -> None:
    client, _ = clocked
    for _ in range(10):
        assert client.post(MESSAGE, json={"text": "hello"}).status_code == 200
    response = client.post(MESSAGE, json={"text": "hello"})
    assert response.status_code == 429
    error = response.json()["error"]
    assert error["code"] == "rate_limited"
    assert "details" not in error
    assert error["request_id"] == response.headers["X-Request-ID"]
    assert response.headers["Retry-After"] == "30"
    assert response.headers["RateLimit-Limit"] == "10"
    assert response.headers["RateLimit-Remaining"] == "0"
    assert response.headers["RateLimit-Reset"] == "30"
    assert response.headers["Cache-Control"] == "no-store"


def test_analyze_endpoints_share_a_bucket(clocked: tuple[TestClient, InMemoryRateLimiter]) -> None:
    client, _ = clocked
    for i in range(10):
        path, body = (MESSAGE, {"text": "hi"}) if i % 2 else (URL, {"url": "example.com"})
        assert client.post(path, json=body).status_code == 200
    assert client.post(URL, json={"url": "example.com"}).status_code == 429
    assert client.post(MESSAGE, json={"text": "hi"}).status_code == 429


def test_feedback_has_its_own_bucket(clocked: tuple[TestClient, InMemoryRateLimiter]) -> None:
    client, _ = clocked
    for _ in range(10):
        client.post(MESSAGE, json={"text": "hello"})
    assert client.post(MESSAGE, json={"text": "hello"}).status_code == 429
    response = client.post(
        FEEDBACK, json={"request_id": "3f2b8c1e-7a4d-4e61-9b0a-5d2c6f8e1a90", "helpful": True}
    )
    assert response.status_code == 404
    assert response.headers["RateLimit-Limit"] == "30"
    assert response.headers["RateLimit-Remaining"] == "29"
    assert response.headers["RateLimit-Reset"] == "3570"


def test_feedback_429(
    make_app: Callable[..., FastAPI],
    store: FakePersistence,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("RATE_LIMIT_FEEDBACK_PER_HOUR", "2")
    app = make_app("production", limiter=InMemoryRateLimiter(clock=lambda: NOW), persistence=store)
    client = TestClient(app, raise_server_exceptions=False)
    body = {"request_id": "3f2b8c1e-7a4d-4e61-9b0a-5d2c6f8e1a90", "helpful": False}
    assert client.post(FEEDBACK, json=body).status_code == 404
    assert client.post(FEEDBACK, json=body).status_code == 404
    response = client.post(FEEDBACK, json=body)
    assert response.status_code == 429
    assert response.headers["Retry-After"] == "3570"
    assert response.headers["RateLimit-Limit"] == "2"


def test_tightest_window_is_reported(
    make_app: Callable[..., FastAPI],
    store: FakePersistence,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    # The day window has fewer requests left than the minute window.
    monkeypatch.setenv("RATE_LIMIT_ANALYZE_PER_DAY", "3")
    app = make_app("production", limiter=InMemoryRateLimiter(clock=lambda: NOW), persistence=store)
    client = TestClient(app, raise_server_exceptions=False)
    first = client.post(MESSAGE, json={"text": "hello"})
    assert first.headers["RateLimit-Limit"] == "3"
    assert first.headers["RateLimit-Remaining"] == "2"
    assert first.headers["RateLimit-Reset"] == str(12 * 3600 - 30)
    client.post(MESSAGE, json={"text": "hello"})
    client.post(MESSAGE, json={"text": "hello"})
    blocked = client.post(MESSAGE, json={"text": "hello"})
    assert blocked.status_code == 429
    assert blocked.headers["Retry-After"] == str(12 * 3600 - 30)
    assert blocked.headers["RateLimit-Remaining"] == "0"


def test_clients_are_counted_separately(
    clocked: tuple[TestClient, InMemoryRateLimiter], monkeypatch: pytest.MonkeyPatch
) -> None:
    client, limiter = clocked
    for _ in range(10):
        client.post(MESSAGE, json={"text": "hello"})
    assert client.post(MESSAGE, json={"text": "hello"}).status_code == 429
    # Without trusted proxies, X-Forwarded-For must not change the client.
    spoofed = client.post(MESSAGE, json={"text": "hello"}, headers={"X-Forwarded-For": "9.9.9.9"})
    assert spoofed.status_code == 429


def test_forwarded_for_used_with_trusted_proxy(
    make_app: Callable[..., FastAPI],
    store: FakePersistence,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("TRUSTED_PROXY_HOPS", "1")
    limiter = InMemoryRateLimiter(clock=lambda: NOW)
    client = TestClient(
        make_app("production", limiter=limiter, persistence=store), raise_server_exceptions=False
    )
    for _ in range(10):
        client.post(
            MESSAGE, json={"text": "hi"}, headers={"X-Forwarded-For": "1.1.1.1, 203.0.113.7"}
        )
    blocked = client.post(
        MESSAGE, json={"text": "hi"}, headers={"X-Forwarded-For": "2.2.2.2, 203.0.113.7"}
    )
    assert blocked.status_code == 429
    other = client.post(MESSAGE, json={"text": "hi"}, headers={"X-Forwarded-For": "203.0.113.8"})
    assert other.status_code == 200


def test_limiter_keys_hold_no_raw_ip(clocked: tuple[TestClient, InMemoryRateLimiter]) -> None:
    client, limiter = clocked
    client.post(MESSAGE, json={"text": "hello"}, headers={"X-Forwarded-For": "203.0.113.7"})
    keys = [key for key, _ in limiter._counts]
    assert len(keys) == 2
    for key in keys:
        scope, window, digest = key.split(":")
        assert scope == "analyze"
        assert window in ("minute", "day")
        assert len(digest) == 64
        assert "203.0.113.7" not in key
        assert "testclient" not in key
