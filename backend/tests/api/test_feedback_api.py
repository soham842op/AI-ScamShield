import uuid

import pytest
from fastapi.testclient import TestClient

from tests.api.fakes import FakePersistence

MESSAGE = "/api/v1/analyze/message"
FEEDBACK = "/api/v1/feedback"
TIMESTAMP_END = "Z"


def _analyze(client: TestClient) -> str:
    response = client.post(MESSAGE, json={"text": "hello"})
    assert response.status_code == 200
    return str(response.json()["request_id"])


def test_feedback_created(api_client: TestClient, store: FakePersistence) -> None:
    request_id = _analyze(api_client)
    response = api_client.post(
        FEEDBACK, json={"request_id": request_id, "helpful": True, "verdict": "correct"}
    )
    assert response.status_code == 201
    body = response.json()
    assert set(body) == {"feedback_id", "received_at"}
    uuid.UUID(body["feedback_id"])
    assert body["received_at"].endswith(TIMESTAMP_END)
    assert response.headers["Cache-Control"] == "no-store"
    assert response.headers["RateLimit-Limit"] == "30"
    assert store.feedback[uuid.UUID(request_id)] == (True, "correct")


def test_verdict_optional_and_null(api_client: TestClient, store: FakePersistence) -> None:
    first = _analyze(api_client)
    second = _analyze(api_client)
    assert (
        api_client.post(FEEDBACK, json={"request_id": first, "helpful": False}).status_code == 201
    )
    response = api_client.post(
        FEEDBACK, json={"request_id": second, "helpful": False, "verdict": None}
    )
    assert response.status_code == 201
    assert store.feedback[uuid.UUID(first)] == (False, None)
    assert store.feedback[uuid.UUID(second)] == (False, None)


@pytest.mark.parametrize("verdict", ["correct", "false_alarm", "missed_scam", "unsure"])
def test_all_verdicts(api_client: TestClient, verdict: str) -> None:
    request_id = _analyze(api_client)
    body = {"request_id": request_id, "helpful": True, "verdict": verdict}
    assert api_client.post(FEEDBACK, json=body).status_code == 201


def test_duplicate_is_409(api_client: TestClient) -> None:
    request_id = _analyze(api_client)
    body = {"request_id": request_id, "helpful": True}
    assert api_client.post(FEEDBACK, json=body).status_code == 201
    response = api_client.post(FEEDBACK, json=body)
    assert response.status_code == 409
    error = response.json()["error"]
    assert error["code"] == "conflict"
    assert error["request_id"] == response.headers["X-Request-ID"]
    assert "details" not in error


def test_unknown_id_is_404(api_client: TestClient) -> None:
    response = api_client.post(FEEDBACK, json={"request_id": str(uuid.uuid4()), "helpful": True})
    assert response.status_code == 404
    error = response.json()["error"]
    assert error["code"] == "not_found"
    assert error["request_id"] == response.headers["X-Request-ID"]


def test_invalid_feedback_is_422(api_client: TestClient) -> None:
    response = api_client.post(FEEDBACK, json={"request_id": "x", "helpful": True})
    assert response.status_code == 422
    assert "RateLimit-Limit" not in response.headers
