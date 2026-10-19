import uuid
from datetime import UTC, datetime, timedelta

import pytest
from sqlalchemy import Connection, text

from app.db import retention
from app.db.repository import (
    increment_rate_limit,
    insert_analysis_record,
    insert_feedback,
    purge_expired,
)
from tests.integration.conftest import point_at
from tests.integration.test_repository import make_record

pytestmark = pytest.mark.integration

NOW = datetime(2026, 10, 16, 12, 0, tzinfo=UTC)


def count(conn: Connection, table: str) -> int:
    return int(conn.execute(text(f"SELECT count(*) FROM {table}")).scalar_one())  # noqa: S608


def add_record(conn: Connection, age: timedelta) -> uuid.UUID:
    rec = make_record(created_at=NOW - age)
    insert_analysis_record(conn, rec)
    return rec.id


def backdate_feedback(conn: Connection, request_id: uuid.UUID, age: timedelta) -> None:
    conn.execute(
        text("UPDATE feedback SET created_at = :t WHERE request_id = :r"),
        {"t": NOW - age, "r": request_id},
    )


def test_retention_constants() -> None:
    assert retention.ANALYSIS_RECORD_RETENTION == timedelta(days=90)
    assert retention.FEEDBACK_RETENTION == timedelta(days=90)
    assert retention.RATE_LIMIT_RETENTION == timedelta(hours=48)


def test_purge_boundaries_and_counts(conn: Connection) -> None:
    old_rec = add_record(conn, timedelta(days=91))
    keep_rec = add_record(conn, timedelta(days=89))
    # Feedback on records that are kept, so only the feedback clock decides.
    fb_old_rec = add_record(conn, timedelta(days=89))
    fb_keep_rec = add_record(conn, timedelta(days=89))
    insert_feedback(conn, fb_old_rec, True, None)
    insert_feedback(conn, fb_keep_rec, True, None)
    backdate_feedback(conn, fb_old_rec, timedelta(days=91))
    backdate_feedback(conn, fb_keep_rec, timedelta(days=89))

    increment_rate_limit(conn, "old", NOW - timedelta(hours=49))
    increment_rate_limit(conn, "keep", NOW - timedelta(hours=47))

    counts = purge_expired(conn, NOW)

    assert counts.analysis_records == 1
    assert counts.feedback == 1
    assert counts.rate_limit_counters == 1

    ids = {r[0] for r in conn.execute(text("SELECT id FROM analysis_records"))}
    assert old_rec not in ids
    assert {keep_rec, fb_old_rec, fb_keep_rec} <= ids
    fb_requests = {r[0] for r in conn.execute(text("SELECT request_id FROM feedback"))}
    assert fb_requests == {fb_keep_rec}
    keys = {r[0] for r in conn.execute(text("SELECT key FROM rate_limit_counters"))}
    assert keys == {"keep"}


def test_purge_cascades_feedback_with_expired_record(conn: Connection) -> None:
    rec = add_record(conn, timedelta(days=91))
    insert_feedback(conn, rec, True, "correct")
    # Feedback itself is recent: it goes only because its record expired. The purge
    # deletes it explicitly first, so it is counted.
    backdate_feedback(conn, rec, timedelta(days=1))
    counts = purge_expired(conn, NOW)
    assert counts.analysis_records == 1
    assert counts.feedback == 1
    assert count(conn, "feedback") == 0


def test_purge_deletes_old_feedback_on_fresh_record(conn: Connection) -> None:
    old_fb = add_record(conn, timedelta(days=1))
    fresh_fb = add_record(conn, timedelta(days=1))
    insert_feedback(conn, old_fb, True, None)
    insert_feedback(conn, fresh_fb, False, "unsure")
    backdate_feedback(conn, old_fb, timedelta(days=91))
    backdate_feedback(conn, fresh_fb, timedelta(days=1))
    counts = purge_expired(conn, NOW)
    assert counts.feedback == 1
    assert counts.analysis_records == 0
    remaining = {r[0] for r in conn.execute(text("SELECT request_id FROM feedback"))}
    assert remaining == {fresh_fb}
    assert count(conn, "analysis_records") == 2


def test_purge_nothing_expired(conn: Connection) -> None:
    add_record(conn, timedelta(days=1))
    counts = purge_expired(conn, NOW)
    assert (counts.analysis_records, counts.feedback, counts.rate_limit_counters) == (0, 0, 0)


def test_naive_datetime_raises(conn: Connection) -> None:
    with pytest.raises(ValueError, match="timezone-aware"):
        purge_expired(conn, datetime(2026, 10, 16, 12, 0))


def test_run_returns_zero_against_test_db(db_env: str) -> None:
    from app.jobs import purge

    assert purge.run() == 0


def test_run_returns_one_when_unreachable(
    db_env: str, monkeypatch: pytest.MonkeyPatch, caplog: pytest.LogCaptureFixture
) -> None:
    from app.jobs import purge

    bad = "postgresql+psycopg://u:secret-pw@127.0.0.1:1/none?connect_timeout=2"
    monkeypatch.setenv("DATABASE_URL", bad)
    point_at(bad)
    try:
        assert purge.run() == 1
    finally:
        monkeypatch.setenv("DATABASE_URL", db_env)
        point_at(db_env)
    assert "secret-pw" not in caplog.text
