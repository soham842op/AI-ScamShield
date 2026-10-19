"""Contract section 9.4: conditions to error codes."""

import json
from typing import Any

import pytest
from fastapi.testclient import TestClient

from tests.api.conftest import post
from tests.api.fakes import FakePersistence

MESSAGE = "/api/v1/analyze/message"
URL = "/api/v1/analyze/url"
FEEDBACK = "/api/v1/feedback"
UUID_OK = "3f2b8c1e-7a4d-4e61-9b0a-5d2c6f8e1a90"
JSON_HEADERS = {"Content-Type": "application/json"}

# path, body, code, issue, field, limit
CASES: list[tuple[str, Any, str, str, str | None, int | None]] = [
    (MESSAGE, {"text": "x" * 10001}, "input_too_long", "max_length", "text", 10000),
    (URL, {"url": "http://example.com/" + "a" * 2048}, "input_too_long", "max_length", "url", 2048),
    (MESSAGE, {}, "validation_error", "required", "text", None),
    (URL, {}, "validation_error", "required", "url", None),
    (MESSAGE, {"text": 5}, "validation_error", "invalid_type", "text", None),
    (MESSAGE, {"text": None}, "validation_error", "invalid_type", "text", None),
    (URL, {"url": ["a"]}, "validation_error", "invalid_type", "url", None),
    (MESSAGE, {"text": ""}, "validation_error", "min_length", "text", None),
    (URL, {"url": ""}, "validation_error", "min_length", "url", None),
    (URL, {"url": "   \t "}, "validation_error", "min_length", "url", None),
    (MESSAGE, {"text": " \n\t "}, "validation_error", "whitespace_only", "text", None),
    (MESSAGE, {"text": "hello\u0000world"}, "validation_error", "nul_character", "text", None),
    (MESSAGE, {"text": "ok", "extra": 1}, "validation_error", "unknown_field", None, None),
    (URL, {"url": "example.com", "extra": 1}, "validation_error", "unknown_field", None, None),
    (
        MESSAGE,
        {"text": "ok", "channel": "fax"},
        "validation_error",
        "invalid_value",
        "channel",
        None,
    ),
    (MESSAGE, {"text": "ok", "channel": 3}, "validation_error", "invalid_type", "channel", None),
    (
        FEEDBACK,
        {"request_id": "nope", "helpful": True},
        "validation_error",
        "invalid_value",
        "request_id",
        None,
    ),
    (
        FEEDBACK,
        {"request_id": UUID_OK, "helpful": "yes"},
        "validation_error",
        "invalid_type",
        "helpful",
        None,
    ),
    (
        FEEDBACK,
        {"request_id": UUID_OK, "helpful": 1},
        "validation_error",
        "invalid_type",
        "helpful",
        None,
    ),
    (
        FEEDBACK,
        {"request_id": UUID_OK, "helpful": True, "verdict": "maybe"},
        "validation_error",
        "invalid_value",
        "verdict",
        None,
    ),
    (FEEDBACK, {"helpful": True}, "validation_error", "required", "request_id", None),
    (FEEDBACK, {"request_id": UUID_OK}, "validation_error", "required", "helpful", None),
    (
        FEEDBACK,
        {"request_id": UUID_OK, "helpful": True, "comment": "x"},
        "validation_error",
        "unknown_field",
        None,
        None,
    ),
    (MESSAGE, [], "validation_error", "invalid_type", None, None),
]


def _details(response: Any) -> list[dict[str, Any]]:
    assert response.status_code == 422
    error = response.json()["error"]
    assert error["request_id"] == response.headers["X-Request-ID"]
    for item in error["details"]:
        assert set(item) <= {"field", "issue", "limit"}
    return list(error["details"])


@pytest.mark.parametrize(("path", "body", "code", "issue", "field", "limit"), CASES)
def test_validation_mapping(
    api_client: TestClient,
    path: str,
    body: Any,
    code: str,
    issue: str,
    field: str | None,
    limit: int | None,
) -> None:
    response = post(api_client, path, body)
    details = _details(response)
    assert response.json()["error"]["code"] == code
    assert details[0]["field"] == field
    assert details[0]["issue"] == issue
    assert details[0].get("limit") == limit


def test_text_length_counts_code_points_after_nfc(api_client: TestClient) -> None:
    # "e" plus a combining accent is one code point after NFC.
    assert post(api_client, MESSAGE, {"text": "é" * 10000}).status_code == 200
    # Characters outside the BMP count once, not as two UTF-16 units.
    assert post(api_client, MESSAGE, {"text": "\U0001f600" * 10000}).status_code == 200
    assert post(api_client, MESSAGE, {"text": "\U0001f600" * 10001}).status_code == 422


def test_text_is_stored_nfc_normalized(api_client: TestClient, store: FakePersistence) -> None:
    assert post(api_client, MESSAGE, {"text": "é" * 3}).status_code == 200
    assert store.records[0].char_count == 3


def test_url_length_counts_after_trimming(api_client: TestClient) -> None:
    base = "example.com/"
    at_limit = " " * 50 + base + "a" * (2048 - len(base)) + " " * 50
    assert post(api_client, URL, {"url": at_limit}).status_code == 200
    over = base + "a" * (2049 - len(base))
    assert post(api_client, URL, {"url": over}).status_code == 422


@pytest.mark.parametrize("path", [MESSAGE, URL, FEEDBACK])
@pytest.mark.parametrize("raw", [b"{", b"", b"not json", b"\xff\xfe\x00", b'{"text": "a",}'])
def test_malformed_json(api_client: TestClient, path: str, raw: bytes) -> None:
    response = api_client.post(path, content=raw, headers=JSON_HEADERS)
    assert response.status_code == 422
    error = response.json()["error"]
    assert error["code"] == "validation_error"
    assert error["details"] == [{"field": None, "issue": "malformed_json"}]


def test_deeply_nested_json_is_malformed(api_client: TestClient) -> None:
    raw = b"[" * 20000 + b"]" * 20000
    response = api_client.post(MESSAGE, content=raw, headers=JSON_HEADERS)
    assert response.status_code == 422


@pytest.mark.parametrize(
    ("path", "field", "rest"),
    [
        (MESSAGE, "text", ""),
        (URL, "url", ""),
        (MESSAGE, "channel", ', "text": "ok"'),
        (FEEDBACK, "verdict", ', "request_id": "' + UUID_OK + '", "helpful": true'),
        (FEEDBACK, "request_id", ', "helpful": true'),
    ],
)
def test_lone_surrogate_rejected(api_client: TestClient, path: str, field: str, rest: str) -> None:
    raw = ('{"' + field + '": "\\ud800"' + rest + "}").encode()
    response = api_client.post(path, content=raw, headers=JSON_HEADERS)
    details = _details(response)
    assert response.json()["error"]["code"] == "validation_error"
    assert {"field": field, "issue": "invalid_unicode"} in details


def test_valid_surrogate_pair_is_accepted(api_client: TestClient) -> None:
    raw = b'{"text": "hi \\ud83d\\ude00"}'
    assert api_client.post(MESSAGE, content=raw, headers=JSON_HEADERS).status_code == 200


def test_422_never_echoes_input(api_client: TestClient) -> None:
    canary = "canary-submitted-value-7731"
    for path, body in (
        (MESSAGE, {"text": canary, "channel": canary}),
        (MESSAGE, {"text": canary, "other-key!" + canary: canary}),
        (URL, {"url": canary + " " + canary}),
        (FEEDBACK, {"request_id": canary, "helpful": canary, "verdict": canary}),
    ):
        response = post(api_client, path, body)
        assert response.status_code == 422
        assert canary not in response.text


@pytest.mark.parametrize(
    "value",
    [
        "http://exa mple.com",
        "http://example.com/a b",
        "exa\u0000mple.com",
        "http://example.com/\u0007",
        "http://:80/x",
        "http://",
    ],
)
def test_invalid_url(api_client: TestClient, value: str) -> None:
    response = post(api_client, URL, {"url": value})
    assert response.status_code == 422
    error = response.json()["error"]
    assert error["code"] == "invalid_url"
    assert error["details"] == [{"field": "url", "issue": "invalid_url"}]


@pytest.mark.parametrize(
    "value",
    [
        "ftp://example.com/x",
        "javascript:alert(1)",
        "data:text/plain,hi",
        "mailto:a@example.com",
        "file:///etc/passwd",
    ],
)
def test_unsupported_scheme(api_client: TestClient, value: str) -> None:
    response = post(api_client, URL, {"url": value})
    assert response.status_code == 422
    error = response.json()["error"]
    assert error["code"] == "unsupported_url_scheme"
    assert error["details"] == [{"field": "url", "issue": "unsupported_scheme"}]


def test_channel_defaults_to_other(api_client: TestClient, store: FakePersistence) -> None:
    assert post(api_client, MESSAGE, {"text": "hello there"}).status_code == 200
    assert store.records[0].channel == "other"


def test_url_whitespace_is_trimmed(api_client: TestClient) -> None:
    assert post(api_client, URL, {"url": "  https://example.com/a  \n"}).status_code == 200


def test_error_body_is_json(api_client: TestClient) -> None:
    response = post(api_client, MESSAGE, {})
    json.loads(response.text)
    assert response.headers["content-type"].startswith("application/json")
