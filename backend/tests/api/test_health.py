import pytest
from fastapi.testclient import TestClient

from app import health


def test_healthz_ok(client: TestClient) -> None:
    response = client.get("/healthz")
    assert response.status_code == 200
    assert response.json() == {"status": "ok"}
    assert response.headers["X-Request-ID"]


def test_readyz_ready(client: TestClient, monkeypatch: pytest.MonkeyPatch) -> None:
    async def ok() -> bool:
        return True

    monkeypatch.setattr(health, "check_database", ok)
    response = client.get("/readyz")
    assert response.status_code == 200
    assert response.json()["status"] == "ready"
    assert response.json()["checks"]["database"] == "ok"


def test_readyz_unavailable(client: TestClient, monkeypatch: pytest.MonkeyPatch) -> None:
    async def down() -> bool:
        return False

    monkeypatch.setattr(health, "check_database", down)
    response = client.get("/readyz")
    assert response.status_code == 503
    assert response.headers["Retry-After"] == "30"
    assert response.json()["status"] == "not_ready"
    assert response.json()["checks"]["database"] == "unavailable"
