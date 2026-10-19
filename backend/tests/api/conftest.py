from collections.abc import Callable
from typing import Any

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient

from app.core.ratelimit import InMemoryRateLimiter
from tests.api.fakes import FakePersistence


@pytest.fixture
def limiter() -> InMemoryRateLimiter:
    return InMemoryRateLimiter()


@pytest.fixture
def store() -> FakePersistence:
    return FakePersistence()


@pytest.fixture
def api_client(
    make_app: Callable[..., FastAPI], limiter: InMemoryRateLimiter, store: FakePersistence
) -> TestClient:
    """The real pipeline with an in-memory limiter and store (no database, no network)."""
    return TestClient(
        make_app("production", limiter=limiter, persistence=store), raise_server_exceptions=False
    )


def post(client: TestClient, path: str, body: Any, **kwargs: Any) -> Any:
    return client.post(path, json=body, **kwargs)
