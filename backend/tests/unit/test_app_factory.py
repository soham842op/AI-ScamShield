from collections.abc import Callable

from fastapi import FastAPI
from fastapi.testclient import TestClient


def test_docs_disabled_outside_development(make_app: Callable[[str], FastAPI]) -> None:
    client = TestClient(make_app("production"), raise_server_exceptions=False)
    for path in ("/docs", "/redoc", "/openapi.json"):
        assert client.get(path).status_code == 404


def test_docs_enabled_in_development(make_app: Callable[[str], FastAPI]) -> None:
    client = TestClient(make_app("development"))
    assert client.get("/openapi.json").status_code == 200
