from collections.abc import Callable, Iterator
from typing import Any

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient

from app.core.config import get_settings
from app.main import create_app

TEST_KEY = "test-client-id-key-0123456789-abcdef"


@pytest.fixture(autouse=True)
def _clear_settings_cache(monkeypatch: pytest.MonkeyPatch) -> Iterator[None]:
    # The app refuses to start without a client-id key outside development.
    monkeypatch.setenv("CLIENT_ID_HASH_KEY", TEST_KEY)
    # Never connected to: tests replace the limiter and the store.
    monkeypatch.setenv("DATABASE_URL", "postgresql+psycopg://u:p@localhost:1/none")
    # A model pinned in a local .env must not leak into tests; they pass a classifier.
    monkeypatch.setenv("MODEL_ARTIFACT_SHA256", "")
    get_settings.cache_clear()
    yield
    get_settings.cache_clear()


@pytest.fixture
def make_app(monkeypatch: pytest.MonkeyPatch) -> Callable[..., FastAPI]:
    def factory(env: str = "production", **overrides: Any) -> FastAPI:
        monkeypatch.setenv("APP_ENV", env)
        get_settings.cache_clear()
        return create_app(**overrides)

    return factory


@pytest.fixture
def client(make_app: Callable[..., FastAPI]) -> TestClient:
    return TestClient(make_app("production"), raise_server_exceptions=False)
