import uuid
from collections.abc import Callable

from fastapi import FastAPI
from fastapi.testclient import TestClient
from pydantic import BaseModel, ConfigDict


class Payload(BaseModel):
    model_config = ConfigDict(extra="forbid")
    text: str


def _app_with_routes(make_app: Callable[[str], FastAPI]) -> FastAPI:
    app = make_app("production")

    @app.post("/_test/echo")
    async def echo(payload: Payload) -> dict[str, str]:
        return {"text": payload.text}

    @app.get("/_test/boom")
    async def boom() -> None:
        raise RuntimeError("secret internal detail")

    return app


def test_404_envelope(client: TestClient) -> None:
    response = client.get("/nope")
    assert response.status_code == 404
    error = response.json()["error"]
    assert set(error) == {"code", "message", "request_id"}
    assert error["code"] == "not_found"
    assert error["request_id"] == response.headers["X-Request-ID"]
    uuid.UUID(error["request_id"])


def test_client_request_id_ignored(client: TestClient) -> None:
    supplied = "11111111-1111-4111-8111-111111111111"
    response = client.get("/nope", headers={"X-Request-ID": supplied})
    assert response.headers["X-Request-ID"] != supplied
    assert response.json()["error"]["request_id"] != supplied


def test_422_does_not_echo_input(make_app: Callable[[str], FastAPI]) -> None:
    client = TestClient(_app_with_routes(make_app), raise_server_exceptions=False)
    submitted = "super-secret-submitted-value"
    response = client.post("/_test/echo", json={"text": submitted, "extra": submitted})
    assert response.status_code == 422
    assert submitted not in response.text
    error = response.json()["error"]
    assert error["code"] == "validation_error"
    assert error["details"]
    for item in error["details"]:
        assert set(item) <= {"field", "issue", "limit"}


def test_500_envelope(make_app: Callable[[str], FastAPI]) -> None:
    client = TestClient(_app_with_routes(make_app), raise_server_exceptions=False)
    response = client.get("/_test/boom")
    assert response.status_code == 500
    assert "secret internal detail" not in response.text
    error = response.json()["error"]
    assert error["code"] == "internal_error"
    assert error["request_id"] == response.headers["X-Request-ID"]
