"""The message endpoint and /readyz with a text model loaded."""

from collections.abc import Callable

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient

from app import health
from app.core.ratelimit import InMemoryRateLimiter
from app.pipeline.aggregator import Thresholds
from tests.api.fakes import FakePersistence
from tests.api.test_analyze_response import MESSAGE, MESSAGES, URL, check_invariants


class FixedClassifier:
    version = "fixed-model-1"
    thresholds = Thresholds(suspicious=0.3, high_risk=0.7)

    def __init__(self, value: float) -> None:
        self.value = value

    def score(self, text: str) -> float:
        return self.value


def _client(make_app: Callable[..., FastAPI], store: FakePersistence, value: float) -> TestClient:
    app = make_app(
        "production",
        limiter=InMemoryRateLimiter(),
        persistence=store,
        classifier=FixedClassifier(value),
    )
    return TestClient(app, raise_server_exceptions=False)


@pytest.mark.parametrize("value", [0.05, 0.5, 0.95])
@pytest.mark.parametrize("text", MESSAGES)
def test_message_invariants_with_model(
    make_app: Callable[..., FastAPI], text: str, value: float
) -> None:
    client = _client(make_app, FakePersistence(), value)
    response = client.post(MESSAGE, json={"text": text, "channel": "sms"})
    assert response.status_code == 200
    body = response.json()
    check_invariants(body)
    assert body["classifier"]["status"] == "ok"
    assert body["classifier"]["raw_score"] == value
    assert body["versions"]["model"] == "fixed-model-1"
    if value >= 0.7:
        assert body["classification"] == "high_risk"
    if body["classification"] != "inconclusive":
        assert body["risk_score"] == round(100 * value)


def test_record_stores_label_score_and_model_version(make_app: Callable[..., FastAPI]) -> None:
    store = FakePersistence()
    client = _client(make_app, store, 0.95)
    response = client.post(MESSAGE, json={"text": "Hi, lunch tomorrow?", "channel": "sms"})
    assert response.status_code == 200
    record = store.records[-1]
    assert record.classifier_label == "scam_like"
    assert record.classifier_raw_score == 0.95
    assert record.versions["model"] == "fixed-model-1"
    assert "classifier_scam_like" in record.signal_ids


def test_url_endpoint_ignores_the_model(make_app: Callable[..., FastAPI]) -> None:
    client = _client(make_app, FakePersistence(), 0.95)
    body = client.post(URL, json={"url": "https://example.com"}).json()
    assert body["classifier"]["status"] == "not_applicable"
    assert body["versions"]["model"] is None
    assert body["risk_score"] is None


def test_readyz_reports_loaded_model(
    make_app: Callable[..., FastAPI], monkeypatch: pytest.MonkeyPatch
) -> None:
    async def ok() -> bool:
        return True

    monkeypatch.setattr(health, "check_database", ok)
    client = _client(make_app, FakePersistence(), 0.5)
    response = client.get("/readyz")
    assert response.status_code == 200
    assert response.json() == {"status": "ready", "checks": {"database": "ok", "model": "ok"}}


def test_readyz_without_model_stays_ready(
    client: TestClient, monkeypatch: pytest.MonkeyPatch
) -> None:
    async def ok() -> bool:
        return True

    monkeypatch.setattr(health, "check_database", ok)
    response = client.get("/readyz")
    assert response.status_code == 200
    assert response.json()["checks"]["model"] == "not_loaded"
