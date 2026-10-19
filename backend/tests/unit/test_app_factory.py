from collections.abc import Callable

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient

from tests.conftest import TEST_KEY


def test_docs_disabled_outside_development(make_app: Callable[[str], FastAPI]) -> None:
    client = TestClient(make_app("production"), raise_server_exceptions=False)
    for path in ("/docs", "/redoc", "/openapi.json"):
        assert client.get(path).status_code == 404


def test_docs_enabled_in_development(make_app: Callable[[str], FastAPI]) -> None:
    client = TestClient(make_app("development"))
    assert client.get("/openapi.json").status_code == 200


def test_refuses_to_start_without_client_id_key_outside_development(
    make_app: Callable[..., FastAPI], monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setenv("CLIENT_ID_HASH_KEY", "")
    with pytest.raises(RuntimeError, match="CLIENT_ID_HASH_KEY"):
        make_app("production")


def test_development_uses_a_random_key_without_config(
    make_app: Callable[..., FastAPI], monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setenv("CLIENT_ID_HASH_KEY", "")
    first = make_app("development").state.services.client_id_key
    second = make_app("development").state.services.client_id_key
    assert len(first) == 32
    assert first != second


def test_configured_key_is_used(make_app: Callable[..., FastAPI]) -> None:
    assert make_app("production").state.services.client_id_key == TEST_KEY.encode()


def test_openapi_available_without_openapi_url(make_app: Callable[..., FastAPI]) -> None:
    app = make_app("production")
    schema = app.openapi()
    assert set(schema["paths"]) >= {
        "/api/v1/analyze/message",
        "/api/v1/analyze/url",
        "/api/v1/feedback",
    }
    for path in ("/api/v1/analyze/message", "/api/v1/analyze/url", "/api/v1/feedback"):
        responses = schema["paths"][path]["post"]["responses"]
        for status in ("413", "415", "422", "429", "503"):
            ref = responses[status]["content"]["application/json"]["schema"]["$ref"]
            assert ref.endswith("/ErrorEnvelope")
    feedback = schema["paths"]["/api/v1/feedback"]["post"]["responses"]
    assert "201" in feedback
    assert feedback["404"] and feedback["409"]
    assert "HTTPValidationError" not in schema["components"]["schemas"]


@pytest.mark.parametrize("key", ["", "short", "change-me", "x" * 31])
def test_weak_client_id_key_refused_outside_development(
    make_app: Callable[..., FastAPI], monkeypatch: pytest.MonkeyPatch, key: str
) -> None:
    monkeypatch.setenv("CLIENT_ID_HASH_KEY", key)
    with pytest.raises(RuntimeError, match="CLIENT_ID_HASH_KEY"):
        make_app("production")


def test_weak_key_allowed_in_development(
    make_app: Callable[..., FastAPI], monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setenv("CLIENT_ID_HASH_KEY", "change-me")
    assert make_app("development").state.services.client_id_key == b"change-me"


def test_missing_database_url_refused_outside_development(
    make_app: Callable[..., FastAPI], monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setenv("DATABASE_URL", "")
    with pytest.raises(RuntimeError, match="DATABASE_URL"):
        make_app("production")
    make_app("development")


def test_app_env_defaults_to_production(monkeypatch: pytest.MonkeyPatch) -> None:
    from app.core.config import Settings

    monkeypatch.delenv("APP_ENV", raising=False)
    assert Settings(_env_file=None).app_env == "production"  # type: ignore[call-arg]
