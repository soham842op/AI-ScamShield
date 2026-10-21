"""Submitted content never reaches the logs, and error bodies never echo it."""

import logging
from typing import Any

import pytest
from fastapi.testclient import TestClient

from tests.security.conftest import FEEDBACK, MESSAGE, URL

CANARY = "zq9canarytoken7"
JSON_HEADERS = {"Content-Type": "application/json"}
KNOWN_ID = "3f2b8c1e-7a4d-4e61-9b0a-5d2c6f8e1a90"

# (label, path, body, headers, expected status). A str body is sent as raw bytes.
Case = tuple[str, str, Any, dict[str, str] | None, int]

CASES: list[Case] = [
    ("message ok", MESSAGE, {"text": f"Send the code {CANARY} now", "channel": "sms"}, None, 200),
    ("message link", MESSAGE, {"text": f"see http://{CANARY}.example/p?q={CANARY}"}, None, 200),
    ("message empty", MESSAGE, {"text": ""}, None, 422),
    ("message nul", MESSAGE, {"text": f"{CANARY}\u0000"}, None, 422),
    ("message long", MESSAGE, {"text": CANARY + "a" * 10001}, None, 422),
    ("message bad channel", MESSAGE, {"text": "hi", "channel": CANARY}, None, 422),
    ("message wrong type", MESSAGE, {"text": [CANARY]}, None, 422),
    ("url ok", URL, {"url": f"http://{CANARY}.example/a"}, None, 200),
    ("url invalid", URL, {"url": f"http://{CANARY} bad/a"}, None, 422),
    ("url scheme", URL, {"url": f"ftp://{CANARY}.example/"}, None, 422),
    ("url too long", URL, {"url": f"http://{CANARY}.example/" + "a" * 2100}, None, 422),
    ("feedback bad uuid", FEEDBACK, {"request_id": CANARY, "helpful": True}, None, 422),
    (
        "feedback bad verdict",
        FEEDBACK,
        {"request_id": KNOWN_ID, "helpful": True, "verdict": CANARY},
        None,
        422,
    ),
    ("malformed json", MESSAGE, '{"text": "' + CANARY + '"', JSON_HEADERS, 422),
    ("oversized", MESSAGE, '{"text": "' + CANARY + "x" * 70000 + '"}', JSON_HEADERS, 413),
    ("wrong content type", MESSAGE, "text=" + CANARY, {"Content-Type": "text/plain"}, 415),
]


def _send(client: TestClient, path: str, body: Any, headers: dict[str, str] | None) -> Any:
    if isinstance(body, str):
        return client.post(path, content=body.encode(), headers=headers)
    return client.post(path, json=body, headers=headers)


def _log_text(record: logging.LogRecord) -> str:
    parts = [record.getMessage(), str(record.msg), repr(record.args), record.exc_text or ""]
    if record.exc_info:
        parts.append(repr(record.exc_info[1]))
    if record.stack_info:
        parts.append(record.stack_info)
    return "\n".join(parts).lower()


@pytest.mark.parametrize("case", CASES, ids=[c[0] for c in CASES])
def test_canary_not_in_logs_or_error_bodies(
    secure_client: TestClient, caplog: pytest.LogCaptureFixture, case: Case
) -> None:
    _, path, body, headers, expected = case
    logging.getLogger().setLevel(logging.DEBUG)
    caplog.set_level(logging.DEBUG)

    response = _send(secure_client, path, body, headers)

    assert response.status_code == expected
    for record in caplog.records:
        assert CANARY not in _log_text(record)
    if response.status_code >= 400:
        assert CANARY not in response.text.lower()
        assert response.headers["content-type"].startswith("application/json")
        assert response.json()["error"]["request_id"] == response.headers["x-request-id"]


def test_canary_not_in_logs_on_feedback_outcomes(
    secure_client: TestClient, caplog: pytest.LogCaptureFixture
) -> None:
    logging.getLogger().setLevel(logging.DEBUG)
    caplog.set_level(logging.DEBUG)
    made = secure_client.post(MESSAGE, json={"text": f"code {CANARY}"})
    request_id = made.json()["request_id"]
    body = {"request_id": request_id, "helpful": True, "verdict": "correct"}
    assert secure_client.post(FEEDBACK, json=body).status_code == 201
    assert secure_client.post(FEEDBACK, json=body).status_code == 409
    assert secure_client.post(FEEDBACK, json={**body, "request_id": KNOWN_ID}).status_code == 404
    for record in caplog.records:
        assert CANARY not in _log_text(record)


def test_unknown_field_name_not_echoed_in_logs(
    secure_client: TestClient, caplog: pytest.LogCaptureFixture
) -> None:
    logging.getLogger().setLevel(logging.DEBUG)
    caplog.set_level(logging.DEBUG)
    response = secure_client.post(MESSAGE, json={"text": "hi", CANARY: 1})
    assert response.status_code == 422
    for record in caplog.records:
        assert CANARY not in _log_text(record)


def test_unknown_field_name_not_echoed_in_body(secure_client: TestClient) -> None:
    response = secure_client.post(MESSAGE, json={"text": "hi", CANARY: 1})
    assert response.status_code == 422
    assert CANARY not in response.text.lower()
