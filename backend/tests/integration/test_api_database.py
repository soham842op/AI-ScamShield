"""The API against a real Postgres: real limiter, real persistence, through create_app()."""

import uuid
from collections.abc import Iterator
from typing import Any

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import text

from app.core.config import get_settings
from app.db.engine import get_engine
from app.main import create_app

pytestmark = pytest.mark.integration

MESSAGE = "/api/v1/analyze/message"
URL = "/api/v1/analyze/url"
FEEDBACK = "/api/v1/feedback"
TABLES = ("feedback", "analysis_records", "rate_limit_counters")
CLIENT_IP = "203.0.113.77"
XFF = {"X-Forwarded-For": CLIENT_IP}
SCAM_TEXT = "Your account is locked. Send the code now to avoid a penalty."


def _wipe() -> None:
    with get_engine().begin() as conn:
        conn.execute(text("TRUNCATE feedback, analysis_records, rate_limit_counters CASCADE"))


def _rows(sql: str, **params: Any) -> list[dict[str, Any]]:
    with get_engine().connect() as conn:
        return [dict(r) for r in conn.execute(text(sql), params).mappings()]


@pytest.fixture
def api(db_env: str, monkeypatch: pytest.MonkeyPatch) -> Iterator[TestClient]:
    monkeypatch.setenv("APP_ENV", "production")
    monkeypatch.setenv("CLIENT_ID_HASH_KEY", "integration-test-key-not-a-secret-0001")
    monkeypatch.setenv("TRUSTED_PROXY_HOPS", "1")
    monkeypatch.setenv("RATE_LIMIT_ANALYZE_PER_MINUTE", "3")
    get_settings.cache_clear()
    _wipe()
    with TestClient(create_app(), raise_server_exceptions=False) as client:
        yield client
    _wipe()
    get_settings.cache_clear()


def _analyze_message(api: TestClient, body: dict[str, Any] | None = None) -> Any:
    return api.post(MESSAGE, json=body or {"text": SCAM_TEXT, "channel": "sms"}, headers=XFF)


class TestPersistence:
    def test_message_row_matches_response(self, api: TestClient) -> None:
        text_in = SCAM_TEXT + " Visit www.example.com/login or http://192.0.2.5/x"
        response = _analyze_message(api, {"text": text_in, "channel": "email"})
        assert response.status_code == 200
        body = response.json()
        assert body["request_id"] == response.headers["x-request-id"]

        rows = _rows("SELECT * FROM analysis_records")
        assert len(rows) == 1
        row = rows[0]
        assert str(row["id"]) == body["request_id"]
        assert row["input_type"] == "message"
        assert row["channel"] == "email"
        assert row["char_count"] == len(text_in)
        assert row["url_count"] == body["url_check"]["urls_found"] == 2
        assert row["classification"] == body["classification"]
        assert row["risk_score"] == body["risk_score"]
        assert row["score_type"] == body["score_type"]
        assert row["signal_ids"] == [s["id"] for s in body["signals"]]
        assert row["url_check_status"] == body["url_check"]["status"]
        statuses = [u["status"] for u in body["url_check"]["urls"]]
        assert row["url_status_counts"] == {s: statuses.count(s) for s in set(statuses)}
        assert row["explanation_source"] == body["explanation"]["source"]
        assert row["versions"] == body["versions"]

    def test_url_row_matches_response(self, api: TestClient) -> None:
        link = "paypa1.example/login"
        response = api.post(URL, json={"url": link}, headers=XFF)
        assert response.status_code == 200
        body = response.json()

        rows = _rows("SELECT * FROM analysis_records")
        assert len(rows) == 1
        row = rows[0]
        assert str(row["id"]) == body["request_id"]
        assert row["input_type"] == "url"
        assert row["channel"] is None
        assert row["char_count"] == len(link)
        assert row["url_count"] == 1
        assert row["classification"] == body["classification"]
        assert row["risk_score"] is None
        assert row["score_type"] == body["score_type"] == "none"
        assert row["signal_ids"] == [s["id"] for s in body["signals"]]
        assert row["url_check_status"] == body["url_check"]["status"]
        assert row["url_status_counts"] == {body["url_check"]["urls"][0]["status"]: 1}
        assert row["explanation_source"] == body["explanation"]["source"]
        assert row["versions"] == body["versions"]


class TestPrivacy:
    def test_canary_in_no_table(self, api: TestClient) -> None:
        canary = "zq9canary" + uuid.uuid4().hex[:12]
        assert (
            _analyze_message(api, {"text": f"Send {canary} http://{canary}.example/p"}).status_code
            == 200
        )
        assert (
            api.post(
                URL, json={"url": f"http://{canary}.example/{canary}"}, headers=XFF
            ).status_code
            == 200
        )
        request_id = _rows("SELECT id FROM analysis_records LIMIT 1")[0]["id"]
        feedback = {"request_id": str(request_id), "helpful": True, "verdict": "correct"}
        assert api.post(FEEDBACK, json=feedback, headers=XFF).status_code == 201

        for table in TABLES:
            dumped = _rows(f"SELECT row_to_json(t)::text AS j FROM {table} t")  # noqa: S608
            assert dumped, table
            for row in dumped:
                assert canary not in row["j"].lower(), table

    def test_no_raw_ip_in_counter_keys(self, api: TestClient) -> None:
        assert _analyze_message(api).status_code == 200
        assert api.post(
            FEEDBACK, json={"request_id": str(uuid.uuid4()), "helpful": True}, headers=XFF
        )
        keys = [r["key"] for r in _rows("SELECT key FROM rate_limit_counters")]
        assert keys
        for key in keys:
            assert CLIENT_IP not in key
            assert "203.0.113" not in key
            assert key.split(":")[0] in {"analyze", "feedback"}


class TestFeedback:
    def test_created_then_duplicate_then_unknown(self, api: TestClient) -> None:
        request_id = _analyze_message(api).json()["request_id"]
        body = {"request_id": request_id, "helpful": False, "verdict": "missed_scam"}
        first = api.post(FEEDBACK, json=body, headers=XFF)
        assert first.status_code == 201
        assert first.json()["feedback_id"]
        second = api.post(FEEDBACK, json=body, headers=XFF)
        assert second.status_code == 409
        assert second.json()["error"]["code"] == "conflict"
        unknown = api.post(
            FEEDBACK, json={"request_id": str(uuid.uuid4()), "helpful": True}, headers=XFF
        )
        assert unknown.status_code == 404
        assert unknown.json()["error"]["code"] == "not_found"
        assert len(_rows("SELECT 1 FROM feedback")) == 1


class TestRateLimit:
    def test_fourth_analyze_is_429_with_headers(self, api: TestClient) -> None:
        for expected_remaining in (2, 1, 0):
            ok = _analyze_message(api)
            assert ok.status_code == 200
            assert ok.headers["RateLimit-Limit"] == "3"
            assert ok.headers["RateLimit-Remaining"] == str(expected_remaining)
        blocked = _analyze_message(api)
        assert blocked.status_code == 429
        assert blocked.json()["error"]["code"] == "rate_limited"
        assert int(blocked.headers["Retry-After"]) >= 1
        assert blocked.headers["RateLimit-Limit"] == "3"
        assert blocked.headers["RateLimit-Remaining"] == "0"
        assert int(blocked.headers["RateLimit-Reset"]) >= 1
        # A blocked request stores no record.
        assert len(_rows("SELECT 1 FROM analysis_records")) == 3

    def test_message_and_url_share_a_bucket(self, api: TestClient) -> None:
        assert _analyze_message(api).status_code == 200
        assert api.post(URL, json={"url": "example.com"}, headers=XFF).status_code == 200
        assert _analyze_message(api).status_code == 200
        assert api.post(URL, json={"url": "example.com"}, headers=XFF).status_code == 429

    def test_feedback_has_its_own_bucket(self, api: TestClient) -> None:
        for _ in range(3):
            assert _analyze_message(api).status_code == 200
        assert _analyze_message(api).status_code == 429
        body = {"request_id": str(uuid.uuid4()), "helpful": True}
        response = api.post(FEEDBACK, json=body, headers=XFF)
        assert response.status_code == 404
        assert response.headers["RateLimit-Limit"] == "30"

    def test_invalid_requests_create_no_counters(self, api: TestClient) -> None:
        invalid: list[Any] = [
            api.post(MESSAGE, json={"text": ""}, headers=XFF),
            api.post(MESSAGE, json={"text": "x" * 10001}, headers=XFF),
            api.post(URL, json={"url": "ftp://example.com"}, headers=XFF),
            api.post(URL, json={"url": "http://exa mple.com"}, headers=XFF),
            api.post(FEEDBACK, json={"request_id": "nope", "helpful": True}, headers=XFF),
            api.post(
                MESSAGE, content=b'{"text": ', headers={**XFF, "Content-Type": "application/json"}
            ),
            api.post(MESSAGE, content=b"text=hi", headers={**XFF, "Content-Type": "text/plain"}),
            api.post(
                MESSAGE,
                content=b'{"text": "' + b"a" * 70000 + b'"}',
                headers={**XFF, "Content-Type": "application/json"},
            ),
        ]
        assert [r.status_code for r in invalid] == [422, 422, 422, 422, 422, 422, 415, 413]
        assert _rows("SELECT 1 FROM rate_limit_counters") == []
        # The whole quota is still available.
        for _ in range(3):
            assert _analyze_message(api).status_code == 200


class TestFailClosed:
    @pytest.fixture
    def dead_api(self, monkeypatch: pytest.MonkeyPatch) -> Iterator[TestClient]:
        monkeypatch.setenv("APP_ENV", "production")
        monkeypatch.setenv("CLIENT_ID_HASH_KEY", "integration-test-key-not-a-secret-0001")
        monkeypatch.setenv("DATABASE_URL", "postgresql+psycopg://u:p@localhost:1/none")
        get_settings.cache_clear()
        get_engine.cache_clear()
        with TestClient(create_app(), raise_server_exceptions=False) as client:
            yield client
        get_engine.cache_clear()
        get_settings.cache_clear()

    def test_endpoints_return_503(self, dead_api: TestClient) -> None:
        requests = [
            (MESSAGE, {"text": SCAM_TEXT}),
            (URL, {"url": "example.com"}),
            (FEEDBACK, {"request_id": str(uuid.uuid4()), "helpful": True}),
        ]
        for path, body in requests:
            response = dead_api.post(path, json=body)
            assert response.status_code == 503, path
            assert response.headers["Retry-After"] == "30"
            error = response.json()["error"]
            assert error["code"] == "service_unavailable"
            assert error["request_id"] == response.headers["x-request-id"]
            assert "localhost" not in response.text

    def test_health_and_readiness(self, dead_api: TestClient) -> None:
        assert dead_api.get("/healthz").status_code == 200
        assert dead_api.get("/readyz").status_code == 503
