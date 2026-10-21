"""Markup in the input comes back only as JSON string data."""

import json

from fastapi.testclient import TestClient

from tests.security.conftest import MESSAGE, URL

PAYLOAD = '<script>alert(1)</script> <img src=x onerror="alert(2)"> http://example.com/a'


def _is_json(response_text: str) -> None:
    assert isinstance(json.loads(response_text), dict)
    assert not response_text.lstrip().startswith("<")


def test_message_payload_is_json_data(secure_client: TestClient) -> None:
    response = secure_client.post(MESSAGE, json={"text": PAYLOAD})
    assert response.status_code == 200
    assert response.headers["content-type"].split(";")[0] == "application/json"
    _is_json(response.text)


def test_url_payload_is_json_data(secure_client: TestClient) -> None:
    response = secure_client.post(URL, json={"url": "http://example.com/<script>alert(1)</script>"})
    assert response.status_code == 200
    assert response.headers["content-type"].split(";")[0] == "application/json"
    _is_json(response.text)


def test_error_response_is_json(secure_client: TestClient) -> None:
    response = secure_client.post(MESSAGE, json={"text": PAYLOAD, "channel": "<script>"})
    assert response.status_code == 422
    assert response.headers["content-type"].split(";")[0] == "application/json"
    assert "<script>" not in response.text
