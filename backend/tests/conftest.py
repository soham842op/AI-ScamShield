from collections.abc import Callable, Iterator

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient

from app.core.config import get_settings
from app.main import create_app


@pytest.fixture(autouse=True)
def _clear_settings_cache() -> Iterator[None]:
    get_settings.cache_clear()
    yield
    get_settings.cache_clear()


@pytest.fixture
def make_app(monkeypatch: pytest.MonkeyPatch) -> Callable[[str], FastAPI]:
    def factory(env: str = "production") -> FastAPI:
        monkeypatch.setenv("APP_ENV", env)
        get_settings.cache_clear()
        return create_app()

    return factory


@pytest.fixture
def client(make_app: Callable[[str], FastAPI]) -> TestClient:
    return TestClient(make_app("production"), raise_server_exceptions=False)
