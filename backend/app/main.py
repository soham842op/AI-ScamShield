import secrets
from typing import Any

from fastapi import FastAPI
from starlette.types import ASGIApp

from app.api.v1 import router as v1_router
from app.core.config import Settings, get_settings
from app.core.errors import register_error_handlers
from app.core.middleware import CatchAllMiddleware, NoStoreMiddleware
from app.core.ratelimit import PostgresRateLimiter, RateLimiter
from app.core.services import (
    Persistence,
    Pipeline,
    PostgresPersistence,
    Services,
    database_engine,
)
from app.health import router as health_router
from app.pipeline.intel import UrlReputationProvider, get_provider

MIN_CLIENT_ID_KEY_LENGTH = 32
PLACEHOLDER_KEY = "change-me"


class ScamShieldApp(FastAPI):
    def build_middleware_stack(self) -> ASGIApp:
        # Wrapped outside Starlette's own error layer, which re-raises after answering.
        return CatchAllMiddleware(super().build_middleware_stack())


def _client_id_key(settings: Settings, development: bool) -> bytes:
    configured = settings.client_id_hash_key.get_secret_value()
    if development:
        # Counters then reset on every restart, which is acceptable for local work.
        return configured.encode() if configured else secrets.token_bytes(32)
    if len(configured) < MIN_CLIENT_ID_KEY_LENGTH or configured == PLACEHOLDER_KEY:
        raise RuntimeError(
            "CLIENT_ID_HASH_KEY must be a secret of at least "
            f"{MIN_CLIENT_ID_KEY_LENGTH} characters outside development"
        )
    return configured.encode()


def create_app(
    *,
    limiter: RateLimiter | None = None,
    persistence: Persistence | None = None,
    provider: UrlReputationProvider | None = None,
    pipeline: Pipeline | None = None,
) -> FastAPI:
    """Build the app. The keyword arguments replace collaborators in tests."""
    settings = get_settings()
    development = settings.app_env == "development"
    key = _client_id_key(settings, development)
    if not development and not settings.database_url.get_secret_value():
        raise RuntimeError("DATABASE_URL must be set outside development")
    app = ScamShieldApp(
        title="AI ScamShield",
        docs_url="/docs" if development else None,
        redoc_url="/redoc" if development else None,
        openapi_url="/openapi.json" if development else None,
        redirect_slashes=False,
    )
    app.state.services = Services(
        limiter=limiter or PostgresRateLimiter(database_engine),
        persistence=persistence or PostgresPersistence(database_engine),
        provider=provider or get_provider(settings.url_intel_provider),
        pipeline=pipeline or Pipeline(),
        client_id_key=key,
    )
    register_error_handlers(app)
    app.add_middleware(NoStoreMiddleware)
    app.include_router(health_router)
    app.include_router(v1_router)
    return app


_app: FastAPI | None = None


def __getattr__(name: str) -> Any:
    # The server imports "app.main:app". Building it on first access keeps a plain
    # import of this module free of start-up checks.
    global _app
    if name == "app":
        if _app is None:
            _app = create_app()
        return _app
    raise AttributeError(name)
