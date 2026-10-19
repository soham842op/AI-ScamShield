import pytest
from alembic import command
from sqlalchemy import inspect

from app.db.engine import get_engine
from tests.integration.conftest import alembic_config

pytestmark = pytest.mark.integration

EXPECTED_COLUMNS = {
    "analysis_records": {
        "id",
        "created_at",
        "input_type",
        "channel",
        "char_count",
        "url_count",
        "classification",
        "risk_score",
        "score_type",
        "classifier_label",
        "classifier_raw_score",
        "signal_ids",
        "url_check_status",
        "url_status_counts",
        "explanation_source",
        "versions",
        "experiment_id",
        "variant",
        "latency_ms",
        "timings_ms",
    },
    "feedback": {"id", "request_id", "created_at", "helpful", "verdict"},
    "rate_limit_counters": {"key", "window_start", "count"},
}

# Name tokens that would suggest a column holds raw content or a device identifier.
FORBIDDEN_TOKENS = {"text", "message", "url", "host", "ip", "agent", "email", "body", "content"}
# Metadata-only names that legitimately contain the "url" token (counts and statuses).
URL_METADATA = {"url_count", "url_check_status", "url_status_counts"}


def _columns() -> dict[str, set[str]]:
    insp = inspect(get_engine())
    return {
        t: {c["name"] for c in insp.get_columns(t)}
        for t in ("analysis_records", "feedback", "rate_limit_counters")
    }


def test_upgrade_creates_expected_columns(db_env: str) -> None:
    assert _columns() == EXPECTED_COLUMNS


def test_no_column_suggests_raw_content(db_env: str) -> None:
    for table, cols in _columns().items():
        for col in cols - URL_METADATA:
            assert not (set(col.split("_")) & FORBIDDEN_TOKENS), f"{table}.{col}"
        assert "user_agent" not in cols


def test_downgrade_to_base_then_upgrade_again(db_env: str) -> None:
    cfg = alembic_config()
    try:
        command.downgrade(cfg, "base")
        get_engine().dispose()
        assert not (set(EXPECTED_COLUMNS) & set(inspect(get_engine()).get_table_names()))
    finally:
        command.upgrade(cfg, "head")
        get_engine().dispose()
    assert _columns() == EXPECTED_COLUMNS


def test_upgrade_is_idempotent_at_head(db_env: str) -> None:
    command.upgrade(alembic_config(), "head")
    assert _columns() == EXPECTED_COLUMNS
