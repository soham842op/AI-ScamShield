import io
from collections.abc import Iterator
from typing import Any

import pytest
from alembic import command
from sqlalchemy import Engine

from app.core.config import get_settings
from app.db import engine as engine_module
from tests.integration.conftest import alembic_config

pytestmark = pytest.mark.integration

URL = "postgresql+psycopg://u:p@127.0.0.1:1/none"


@pytest.fixture
def built_engine(monkeypatch: pytest.MonkeyPatch) -> Iterator[Engine]:
    monkeypatch.setenv("DATABASE_URL", URL)
    get_settings.cache_clear()
    engine_module.get_engine.cache_clear()
    yield engine_module.get_engine()
    engine_module.get_engine.cache_clear()
    get_settings.cache_clear()


def test_pool_timeout_and_hidden_parameters(built_engine: Engine) -> None:
    assert built_engine.pool.timeout() == 5  # type: ignore[attr-defined]
    assert built_engine.hide_parameters is True


def test_connect_args(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("DATABASE_URL", URL)
    get_settings.cache_clear()
    engine_module.get_engine.cache_clear()
    seen: dict[str, Any] = {}

    def fake_create_engine(url: str, **kwargs: Any) -> object:
        seen.update(kwargs)
        return object()

    monkeypatch.setattr(engine_module, "create_engine", fake_create_engine)
    try:
        engine_module.get_engine()
    finally:
        engine_module.get_engine.cache_clear()
        get_settings.cache_clear()
    assert seen["connect_args"]["connect_timeout"] == 3
    assert "statement_timeout=5000" in seen["connect_args"]["options"]
    assert seen["pool_timeout"] == 5
    assert seen["hide_parameters"] is True


class TestMigrationUrlPrecedence:
    """env.py runs at import under alembic, so exercise it through offline SQL generation."""

    def run_offline(self) -> str:
        cfg = alembic_config()
        buf = io.StringIO()
        cfg.output_buffer = buf
        command.upgrade(cfg, "head", sql=True)
        return buf.getvalue()

    def test_migration_url_wins_over_database_url(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setenv("DATABASE_URL", "nosuchdialect://x/y")
        monkeypatch.setenv("MIGRATION_DATABASE_URL", URL)
        get_settings.cache_clear()
        try:
            assert "CREATE TABLE analysis_records" in self.run_offline()
        finally:
            get_settings.cache_clear()

    def test_falls_back_to_database_url(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.delenv("MIGRATION_DATABASE_URL", raising=False)
        monkeypatch.setenv("DATABASE_URL", "nosuchdialect://x/y")
        get_settings.cache_clear()
        try:
            with pytest.raises(Exception, match="nosuchdialect"):
                self.run_offline()
        finally:
            get_settings.cache_clear()
