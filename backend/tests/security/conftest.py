from collections.abc import Callable

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient

from app.core.ratelimit import InMemoryRateLimiter
from tests.api.fakes import FakePersistence

MESSAGE = "/api/v1/analyze/message"
URL = "/api/v1/analyze/url"
FEEDBACK = "/api/v1/feedback"


@pytest.fixture
def secure_client(make_app: Callable[..., FastAPI]) -> TestClient:
    """The real pipeline with an in-memory limiter and store: no database, no network."""
    app = make_app("production", limiter=InMemoryRateLimiter(), persistence=FakePersistence())
    return TestClient(app, raise_server_exceptions=False)
