"""Response shape, headers, persistence and the invariants of contract 5.8."""

import re
import uuid
from collections.abc import Callable
from typing import Any

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient

from app.core.ratelimit import InMemoryRateLimiter
from tests.api.fakes import NOT_A_GUARANTEE, FakePersistence, fake_pipeline

MESSAGE = "/api/v1/analyze/message"
URL = "/api/v1/analyze/url"
TIMESTAMP = re.compile(r"^\d{4}-\d\d-\d\dT\d\d:\d\d:\d\d(\.\d{1,3})?Z$")

MESSAGES = [
    "Your account will be suspended today. Verify at https://paypa1-secure.example/login",
    "Hi, are we still meeting for lunch tomorrow?",
    "You have won a prize! Send a gift card code to claim it. Visit www.example.com now",
    " ".join(f"http://example.com/{i}" for i in range(12)),
    "Call us. mailto:a@example.com tel:+15550100 javascript:alert(1)",
]
URLS = [
    "paypa1.example/login",
    "https://example.com",
    "http://192.0.2.1:8080/x",
    "xn--e1afmkfd.example",
]


def check_invariants(body: dict[str, Any]) -> None:
    assert body["schema_version"] == "1.0"
    uuid.UUID(body["request_id"])
    assert TIMESTAMP.match(body["created_at"])
    cls = body["classifier"]
    check = body["url_check"]
    urls = check["urls"]
    # I1
    assert (body["risk_score"] is not None) == (body["score_type"] == "heuristic")
    assert (body["risk_score"] is not None) == (body["score_basis"] == "text_classifier")
    if body["risk_score"] is None:
        assert body["score_type"] == "none"
        assert body["score_basis"] is None
    # I2
    assert (cls["status"] == "ok") == (cls["label"] is not None) == (cls["raw_score"] is not None)
    # I3
    if body["input_type"] == "url":
        assert cls["status"] == "not_applicable"
        assert body["risk_score"] is None
    # I4
    none_found = check["urls_found"] == 0
    assert none_found == (urls == []) == (check["status"] == "not_applicable")
    assert none_found == (check["provider"] is None)
    # I5
    assert len(urls) == min(check["urls_found"], 10)
    assert check["urls_truncated"] == (check["urls_found"] > 10)
    # I6
    checked = [u for u in urls if u["status"] in ("flagged", "no_match")]
    assert check["urls_checked"] == len(checked)
    assert (check["checked_at"] is not None) == (len(checked) > 0)
    if check["checked_at"]:
        assert TIMESTAMP.match(check["checked_at"])
    # I7
    for u in urls:
        assert (u["reason"] is None) == (u["status"] in ("flagged", "no_match"))
        if u["status"] == "unknown":
            assert u["reason"] in ("provider_timeout", "provider_error")
        if u["status"] == "not_checked":
            assert u["reason"] in ("provider_not_configured", "quota_exhausted")
        assert bool(u["threat_types"]) == (u["status"] == "flagged")
    # I8
    if not none_found:
        assert check["provider"] == "none"
    # I9, I10
    assert (body["explanation"]["source"] == "llm") == (body["versions"]["prompt"] is not None)
    assert (body["versions"]["model"] is not None) == (cls["status"] == "ok")
    # I11
    ids = [s["id"] for s in body["signals"]]
    assert len(ids) == len(set(ids))
    for s in body["signals"]:
        assert s["evidence_excerpt"] is None or len(s["evidence_excerpt"]) <= 120
    assert NOT_A_GUARANTEE in body["limitations"]
    assert body["limitations"][0] == NOT_A_GUARANTEE
    assert body["recommendations"]
    assert body["experiment"] is None
    assert isinstance(body["latency_ms"], int)
    assert body["latency_ms"] >= 0
    # No part of the response may call anything safe.
    assert "safe" not in body["explanation"]["text"].lower().replace("not mean they are safe", "")


@pytest.mark.parametrize("text", MESSAGES)
def test_message_invariants(api_client: TestClient, text: str) -> None:
    response = api_client.post(MESSAGE, json={"text": text, "channel": "sms"})
    assert response.status_code == 200
    body = response.json()
    assert body["input_type"] == "message"
    check_invariants(body)


@pytest.mark.parametrize("url", URLS)
def test_url_invariants(api_client: TestClient, url: str) -> None:
    response = api_client.post(URL, json={"url": url})
    assert response.status_code == 200
    body = response.json()
    assert body["input_type"] == "url"
    assert body["url_check"]["urls_found"] == 1
    assert len(body["url_check"]["urls"]) == 1
    check_invariants(body)


def test_headers_and_ids(api_client: TestClient) -> None:
    response = api_client.post(MESSAGE, json={"text": "hello"})
    assert response.status_code == 200
    assert response.headers["Cache-Control"] == "no-store"
    assert response.json()["request_id"] == response.headers["X-Request-ID"]
    other = api_client.post(MESSAGE, json={"text": "hello"})
    assert other.headers["X-Request-ID"] != response.headers["X-Request-ID"]


@pytest.mark.parametrize(
    "request_args",
    [
        ("get", "/api/v1/nope", None),
        ("get", MESSAGE, None),
        ("post", MESSAGE, {"text": ""}),
        ("get", "/api/anything", None),
    ],
)
def test_cache_control_on_every_api_response(
    api_client: TestClient, request_args: tuple[str, str, Any]
) -> None:
    method, path, body = request_args
    response = api_client.request(method, path, json=body)
    assert response.status_code >= 400
    assert response.headers["Cache-Control"] == "no-store"


def test_health_has_no_cache_control(api_client: TestClient) -> None:
    assert "Cache-Control" not in api_client.get("/healthz").headers


def test_persisted_record_message(api_client: TestClient, store: FakePersistence) -> None:
    text = "Verify now at http://example.com/a and http://example.com/b"
    response = api_client.post(MESSAGE, json={"text": text, "channel": "email"})
    body = response.json()
    (record,) = store.records
    assert str(record.id) == body["request_id"] == response.headers["X-Request-ID"]
    assert record.input_type == "message"
    assert record.channel == "email"
    assert record.char_count == len(text)
    assert record.url_count == body["url_check"]["urls_found"] == 2
    assert record.classification == body["classification"]
    assert record.signal_ids == [s["id"] for s in body["signals"]]
    assert record.url_check_status == body["url_check"]["status"]
    assert record.url_status_counts == {"not_checked": 2}
    assert record.versions == body["versions"]
    assert record.latency_ms == body["latency_ms"]
    assert record.created_at is not None
    assert record.created_at.tzinfo is not None
    assert record.created_at.isoformat().replace("+00:00", "Z")[:19] == body["created_at"][:19]
    assert "rules" in record.timings_ms
    assert text not in repr(record)
    assert "example.com" not in repr(record)


def test_persisted_record_url(api_client: TestClient, store: FakePersistence) -> None:
    url = "  paypa1.example/login  "
    body = api_client.post(URL, json={"url": url}).json()
    (record,) = store.records
    assert record.input_type == "url"
    assert record.channel is None
    assert record.char_count == len(url.strip())
    assert record.url_count == 1
    assert str(record.id) == body["request_id"]
    assert "paypa1" not in repr(record)


def test_created_at_matches_stored_time(api_client: TestClient, store: FakePersistence) -> None:
    body = api_client.post(MESSAGE, json={"text": "hello"}).json()
    created = store.records[0].created_at
    assert created is not None
    assert created.microsecond % 1000 == 0
    assert body["created_at"].endswith("Z")


def test_analysis_is_stored_before_200(
    make_app: Callable[..., FastAPI], store: FakePersistence
) -> None:
    app = make_app(
        "production", limiter=InMemoryRateLimiter(), persistence=store, pipeline=fake_pipeline()
    )
    client = TestClient(app, raise_server_exceptions=False)
    response = client.post(MESSAGE, json={"text": "hello"})
    assert response.status_code == 200
    assert [str(r.id) for r in store.records] == [response.json()["request_id"]]


def test_provider_from_settings(
    make_app: Callable[..., FastAPI], monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setenv("URL_INTEL_PROVIDER", "no-such-provider")
    with pytest.raises(ValueError):
        make_app("production")


def test_pipeline_receives_configured_provider(
    make_app: Callable[..., FastAPI], store: FakePersistence
) -> None:
    seen: list[object] = []
    pipeline = fake_pipeline()

    async def message(text: str, channel: str, *, provider: object) -> object:
        seen.append(provider)
        return await pipeline.analyze_message(text, channel, provider=provider)

    from app.core.services import Pipeline

    app = make_app(
        "production",
        limiter=InMemoryRateLimiter(),
        persistence=store,
        pipeline=Pipeline(analyze_message=message, analyze_url=pipeline.analyze_url),
    )
    TestClient(app, raise_server_exceptions=False).post(MESSAGE, json={"text": "hello"})
    assert len(seen) == 1
    assert getattr(seen[0], "provider_id", None) == "none"
