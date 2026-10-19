from functools import lru_cache

from sqlalchemy import Engine, create_engine

from app.core.config import get_settings


def get_database_url() -> str:
    url = get_settings().database_url.get_secret_value()
    if not url:
        raise RuntimeError("DATABASE_URL is not set")
    return url


@lru_cache
def get_engine() -> Engine:
    # Timeouts keep a dead database from hanging a request. Callers must treat any
    # sqlalchemy.exc.SQLAlchemyError (including the pool's TimeoutError) as "database
    # unavailable". hide_parameters keeps bound values (for example the limiter key)
    # out of exception strings.
    return create_engine(
        get_database_url(),
        pool_pre_ping=True,
        pool_timeout=5,
        hide_parameters=True,
        connect_args={"connect_timeout": 3, "options": "-c statement_timeout=5000"},
    )
