import os
from collections.abc import Iterator
from pathlib import Path

import pytest
from alembic import command
from alembic.config import Config
from sqlalchemy import Connection

from app.core.config import get_settings
from app.db.engine import get_engine

BACKEND_DIR = Path(__file__).resolve().parents[2]
ALEMBIC_INI = BACKEND_DIR / "alembic.ini"


def _clear_caches() -> None:
    get_settings.cache_clear()
    get_engine.cache_clear()


def point_at(url: str) -> None:
    os.environ["DATABASE_URL"] = url
    _clear_caches()


def alembic_config() -> Config:
    cfg = Config(str(ALEMBIC_INI))
    cfg.set_main_option("script_location", str(BACKEND_DIR / "migrations"))
    return cfg


@pytest.fixture(scope="session")
def test_database_url() -> str:
    url = os.environ.get("TEST_DATABASE_URL", "")
    if not url:
        pytest.skip("TEST_DATABASE_URL is not set")
    return url


@pytest.fixture(scope="session")
def migrated_db(test_database_url: str) -> Iterator[str]:
    previous = os.environ.get("DATABASE_URL")
    point_at(test_database_url)
    command.upgrade(alembic_config(), "head")
    try:
        yield test_database_url
    finally:
        get_engine().dispose()
        if previous is None:
            os.environ.pop("DATABASE_URL", None)
        else:
            os.environ["DATABASE_URL"] = previous
        _clear_caches()


@pytest.fixture
def db_env(migrated_db: str, monkeypatch: pytest.MonkeyPatch) -> str:
    """DATABASE_URL points at the test database for this test."""
    monkeypatch.setenv("DATABASE_URL", migrated_db)
    _clear_caches()
    return migrated_db


@pytest.fixture
def conn(db_env: str) -> Iterator[Connection]:
    """A connection inside a transaction that is rolled back after the test."""
    with get_engine().connect() as connection:
        transaction = connection.begin()
        try:
            yield connection
        finally:
            transaction.rollback()
