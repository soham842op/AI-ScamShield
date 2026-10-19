"""Contract section 1: the first failing check is returned."""

from collections.abc import Iterator

import pytest
from fastapi.testclient import TestClient

from app.core.ratelimit import InMemoryRateLimiter
from tests.api.fakes import FakePersistence

MESSAGE = "/api/v1/analyze/message"
PATHS = [MESSAGE, "/api/v1/analyze/url", "/api/v1/feedback"]
BIG = b"x" * (64 * 1024 + 1)
JSON_HEADERS = {"Content-Type": "application/json"}


def test_route_before_content_type(api_client: TestClient) -> None:
    response = api_client.post("/api/v1/nope", content=b"x", headers={"Content-Type": "text/plain"})
    assert response.status_code == 404
    assert response.json()["error"]["code"] == "not_found"


def test_method_before_content_type(api_client: TestClient) -> None:
    response = api_client.get(MESSAGE)
    assert response.status_code == 405
    assert response.json()["error"]["code"] == "method_not_allowed"


@pytest.mark.parametrize("path", PATHS)
@pytest.mark.parametrize(
    "content_type",
    [
        None,
        "text/plain",
        "application/x-www-form-urlencoded",
        "application/json; charset=latin-1",
        "application/jsonx",
        "application/json; boundary=x",
        "application/json; charset=utf-8; x=y",
    ],
)
def test_415_wins_over_oversized_body(
    api_client: TestClient, path: str, content_type: str | None
) -> None:
    headers = {"Content-Type": content_type} if content_type else {}
    response = api_client.post(path, content=BIG, headers=headers)
    assert response.status_code == 415
    error = response.json()["error"]
    assert error["code"] == "unsupported_media_type"
    assert error["request_id"] == response.headers["X-Request-ID"]


@pytest.mark.parametrize(
    "content_type",
    [
        "application/json",
        "Application/JSON",
        "application/json; charset=utf-8",
        "application/json;charset=UTF-8",
        'application/json; charset="utf-8"',
    ],
)
def test_json_content_types_accepted(api_client: TestClient, content_type: str) -> None:
    response = api_client.post(
        MESSAGE, content=b'{"text": "hello"}', headers={"Content-Type": content_type}
    )
    assert response.status_code == 200


@pytest.mark.parametrize("path", PATHS)
def test_413_by_content_length(api_client: TestClient, path: str) -> None:
    response = api_client.post(path, content=BIG, headers=JSON_HEADERS)
    assert response.status_code == 413
    assert response.json()["error"]["code"] == "payload_too_large"


@pytest.mark.parametrize("path", PATHS)
def test_413_by_chunked_stream(api_client: TestClient, path: str) -> None:
    def chunks() -> Iterator[bytes]:
        for _ in range(65):
            yield b"x" * 1024
        yield b"y"

    response = api_client.post(path, content=chunks(), headers=JSON_HEADERS)
    assert response.status_code == 413


def test_body_at_limit_is_accepted(api_client: TestClient) -> None:
    head = b'{"text": "hello"'
    raw = head + b" " * (64 * 1024 - len(head) - 1) + b"}"
    assert len(raw) == 64 * 1024
    assert api_client.post(MESSAGE, content=raw, headers=JSON_HEADERS).status_code == 200


def test_413_before_json_parse(api_client: TestClient) -> None:
    response = api_client.post(MESSAGE, content=BIG, headers=JSON_HEADERS)
    assert response.status_code == 413


def test_malformed_json_before_schema(api_client: TestClient) -> None:
    response = api_client.post("/api/v1/feedback", content=b'{"nope": ', headers=JSON_HEADERS)
    assert response.json()["error"]["details"][0]["issue"] == "malformed_json"


@pytest.mark.parametrize(
    ("path", "body"),
    [
        (MESSAGE, {"text": ""}),
        (MESSAGE, {"text": "ok", "bad": 1}),
        ("/api/v1/analyze/url", {"url": "ftp://example.com"}),
        ("/api/v1/analyze/url", {"url": "http://exa mple.com"}),
        ("/api/v1/feedback", {"request_id": "x", "helpful": True}),
    ],
)
def test_invalid_requests_do_not_consume_quota(
    api_client: TestClient, limiter: InMemoryRateLimiter, path: str, body: dict[str, object]
) -> None:
    for _ in range(30):
        assert api_client.post(path, json=body).status_code == 422
    assert limiter._counts == {}
    for _ in range(10):
        assert api_client.post(MESSAGE, json={"text": "hello"}).status_code == 200
    assert api_client.post(MESSAGE, json={"text": "hello"}).status_code == 429


def test_early_rejections_do_not_consume_quota(
    api_client: TestClient, limiter: InMemoryRateLimiter, store: FakePersistence
) -> None:
    api_client.post(MESSAGE, content=b"{}", headers={"Content-Type": "text/plain"})
    api_client.post(MESSAGE, content=BIG, headers=JSON_HEADERS)
    api_client.post(MESSAGE, content=b"{", headers=JSON_HEADERS)
    assert limiter._counts == {}
    assert store.records == []


def test_rate_limit_comes_before_the_handler(
    api_client: TestClient, store: FakePersistence
) -> None:
    for _ in range(10):
        api_client.post(MESSAGE, json={"text": "hello"})
    assert len(store.records) == 10
    assert api_client.post(MESSAGE, json={"text": "hello"}).status_code == 429
    assert len(store.records) == 10
