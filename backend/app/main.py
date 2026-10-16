from fastapi import FastAPI

from app.core.config import get_settings
from app.core.errors import register_error_handlers
from app.health import router as health_router


def create_app() -> FastAPI:
    settings = get_settings()
    development = settings.app_env == "development"
    app = FastAPI(
        title="AI ScamShield",
        docs_url="/docs" if development else None,
        redoc_url="/redoc" if development else None,
        openapi_url="/openapi.json" if development else None,
    )
    register_error_handlers(app)
    app.include_router(health_router)
    return app


app = create_app()
