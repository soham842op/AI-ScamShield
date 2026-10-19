import uuid
from dataclasses import replace
from datetime import UTC, datetime, timedelta
from typing import Any

import pytest
from sqlalchemy import Connection, text
from sqlalchemy.exc import IntegrityError

from app.db.repository import (
    AnalysisRecord,
    FeedbackOutcome,
    increment_rate_limit,
    insert_analysis_record,
    insert_feedback,
)

pytestmark = pytest.mark.integration


def make_record(**overrides: Any) -> AnalysisRecord:
    base = AnalysisRecord(
        id=uuid.uuid4(),
        input_type="message",
        channel="sms",
        char_count=120,
        url_count=1,
        classification="suspicious",
        risk_score=55,
        score_type="heuristic",
        classifier_label="scam_like",
        classifier_raw_score=0.7,
        signal_ids=["urgency", "payment_request"],
        url_check_status="not_checked",
        url_status_counts={"not_checked": 1},
        explanation_source="template",
        versions={"model": "m1", "rules": "r1"},
        latency_ms=42,
        timings_ms={"total": 42},
        experiment_id="exp1",
        variant="a",
    )
    return replace(base, **overrides)


def fetch(conn: Connection, record_id: uuid.UUID) -> dict[str, Any]:
    row = (
        conn.execute(text("SELECT * FROM analysis_records WHERE id = :id"), {"id": record_id})
        .mappings()
        .one()
    )
    return dict(row)


class TestInsertAnalysisRecord:
    def test_message_round_trip(self, conn: Connection) -> None:
        rec = make_record()
        insert_analysis_record(conn, rec)
        row = fetch(conn, rec.id)
        assert row["input_type"] == "message"
        assert row["channel"] == "sms"
        assert row["char_count"] == 120
        assert row["url_count"] == 1
        assert row["classification"] == "suspicious"
        assert row["risk_score"] == 55
        assert row["score_type"] == "heuristic"
        assert row["classifier_label"] == "scam_like"
        assert row["classifier_raw_score"] == pytest.approx(0.7)
        assert row["signal_ids"] == ["urgency", "payment_request"]
        assert row["url_check_status"] == "not_checked"
        assert row["url_status_counts"] == {"not_checked": 1}
        assert row["explanation_source"] == "template"
        assert row["versions"] == {"model": "m1", "rules": "r1"}
        assert row["timings_ms"] == {"total": 42}
        assert row["experiment_id"] == "exp1"
        assert row["variant"] == "a"
        assert row["latency_ms"] == 42
        assert row["created_at"].tzinfo is not None

    def test_explicit_created_at_is_used(self, conn: Connection) -> None:
        when = datetime(2026, 1, 2, 3, 4, 5, tzinfo=UTC)
        rec = make_record(created_at=when)
        insert_analysis_record(conn, rec)
        assert fetch(conn, rec.id)["created_at"] == when

    def test_url_record_with_null_channel(self, conn: Connection) -> None:
        rec = make_record(input_type="url", channel=None, char_count=30)
        insert_analysis_record(conn, rec)
        row = fetch(conn, rec.id)
        assert row["input_type"] == "url"
        assert row["channel"] is None

    def test_message_with_null_channel_rejected(self, conn: Connection) -> None:
        with pytest.raises(IntegrityError, match="channel_matches_input"):
            insert_analysis_record(conn, make_record(channel=None))

    def test_url_with_channel_rejected(self, conn: Connection) -> None:
        with pytest.raises(IntegrityError, match="channel_matches_input"):
            insert_analysis_record(conn, make_record(input_type="url", channel="sms"))

    def test_invalid_classification_rejected(self, conn: Connection) -> None:
        with pytest.raises(IntegrityError, match="ck_analysis_records_classification"):
            insert_analysis_record(conn, make_record(classification="safe"))

    @pytest.mark.parametrize("score", [-1, 101])
    def test_risk_score_out_of_range_rejected(self, conn: Connection, score: int) -> None:
        with pytest.raises(IntegrityError, match="ck_analysis_records_risk_score"):
            insert_analysis_record(conn, make_record(risk_score=score))

    @pytest.mark.parametrize("score", [0, 100])
    def test_risk_score_bounds_accepted(self, conn: Connection, score: int) -> None:
        insert_analysis_record(conn, make_record(risk_score=score))


class TestInsertFeedback:
    def test_created(self, conn: Connection) -> None:
        rec = make_record()
        insert_analysis_record(conn, rec)
        result = insert_feedback(conn, rec.id, True, "correct")
        assert result.outcome is FeedbackOutcome.CREATED
        assert result.feedback_id is not None
        assert result.created_at is not None
        assert result.created_at.tzinfo is not None

    def test_null_verdict_allowed(self, conn: Connection) -> None:
        rec = make_record()
        insert_analysis_record(conn, rec)
        assert insert_feedback(conn, rec.id, False, None).outcome is FeedbackOutcome.CREATED

    def test_duplicate(self, conn: Connection) -> None:
        rec = make_record()
        insert_analysis_record(conn, rec)
        insert_feedback(conn, rec.id, True, "correct")
        second = insert_feedback(conn, rec.id, False, "unsure")
        assert second.outcome is FeedbackOutcome.DUPLICATE
        assert second.feedback_id is None
        assert second.created_at is None

    def test_unknown_request(self, conn: Connection) -> None:
        result = insert_feedback(conn, uuid.uuid4(), True, None)
        assert result.outcome is FeedbackOutcome.UNKNOWN_REQUEST
        assert result.feedback_id is None

    def test_invalid_verdict_rejected(self, conn: Connection) -> None:
        rec = make_record()
        insert_analysis_record(conn, rec)
        with pytest.raises(IntegrityError, match="ck_feedback_verdict"):
            insert_feedback(conn, rec.id, True, "bogus")


class TestIncrementRateLimit:
    def test_counts_up_per_window(self, conn: Connection) -> None:
        window = datetime(2026, 10, 16, 12, 0, tzinfo=UTC)
        assert [increment_rate_limit(conn, "k", window) for _ in range(3)] == [1, 2, 3]

    def test_new_window_restarts(self, conn: Connection) -> None:
        window = datetime(2026, 10, 16, 12, 0, tzinfo=UTC)
        assert increment_rate_limit(conn, "k", window) == 1
        assert increment_rate_limit(conn, "k", window) == 2
        assert increment_rate_limit(conn, "k", window + timedelta(minutes=1)) == 1

    def test_keys_are_independent(self, conn: Connection) -> None:
        window = datetime(2026, 10, 16, 12, 0, tzinfo=UTC)
        assert increment_rate_limit(conn, "a", window) == 1
        assert increment_rate_limit(conn, "b", window) == 1
