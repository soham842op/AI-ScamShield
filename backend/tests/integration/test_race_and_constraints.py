from concurrent.futures import ThreadPoolExecutor
from concurrent.futures import TimeoutError as FutureTimeout
from datetime import UTC, datetime
from typing import Any

import pytest
from sqlalchemy import Connection, text
from sqlalchemy.exc import DBAPIError, IntegrityError

from app.db.engine import get_engine
from app.db.repository import (
    FeedbackOutcome,
    increment_rate_limit,
    insert_analysis_record,
    insert_feedback,
)
from tests.integration.test_repository import make_record

pytestmark = pytest.mark.integration


class TestPurgeRace:
    def test_feedback_waits_for_uncommitted_delete_then_unknown(self, db_env: str) -> None:
        engine = get_engine()
        rec = make_record()
        with engine.begin() as setup:
            insert_analysis_record(setup, rec)
        conn_a = engine.connect()
        conn_b = engine.connect()
        pool = ThreadPoolExecutor(max_workers=1)
        try:
            tx_a = conn_a.begin()
            conn_a.execute(text("DELETE FROM analysis_records WHERE id = :i"), {"i": rec.id})

            def run_b() -> FeedbackOutcome:
                with conn_b.begin():
                    return insert_feedback(conn_b, rec.id, True, "correct").outcome

            future = pool.submit(run_b)
            with pytest.raises(FutureTimeout):
                future.result(timeout=1.0)  # still blocked on the row lock
            tx_a.commit()
            assert future.result(timeout=4.0) is FeedbackOutcome.UNKNOWN_REQUEST
            # B's connection is still usable.
            assert conn_b.execute(text("SELECT 1")).scalar_one() == 1
        finally:
            pool.shutdown(wait=True, cancel_futures=True)
            conn_a.close()
            conn_b.close()
            with engine.begin() as cleanup:
                cleanup.execute(text("DELETE FROM feedback WHERE request_id = :i"), {"i": rec.id})
                cleanup.execute(text("DELETE FROM analysis_records WHERE id = :i"), {"i": rec.id})


class TestReRaise:
    def test_invalid_verdict_still_raises(self, conn: Connection) -> None:
        rec = make_record()
        insert_analysis_record(conn, rec)
        with pytest.raises(IntegrityError):
            insert_feedback(conn, rec.id, True, "not_a_verdict")


class TestNaiveDatetimes:
    NAIVE = datetime(2026, 10, 16, 12, 0)
    AWARE = datetime(2026, 10, 16, 12, 0, tzinfo=UTC)

    def test_rate_limit_naive_raises(self, conn: Connection) -> None:
        with pytest.raises(ValueError, match="timezone-aware"):
            increment_rate_limit(conn, "k", self.NAIVE)

    def test_rate_limit_aware_works(self, conn: Connection) -> None:
        assert increment_rate_limit(conn, "k", self.AWARE) == 1
        assert increment_rate_limit(conn, "k", self.AWARE) == 2

    def test_record_naive_created_at_raises(self, conn: Connection) -> None:
        with pytest.raises(ValueError, match="timezone-aware"):
            insert_analysis_record(conn, make_record(created_at=self.NAIVE))

    def test_record_aware_and_none_created_at_work(self, conn: Connection) -> None:
        aware = make_record(created_at=self.AWARE)
        none = make_record(created_at=None)
        insert_analysis_record(conn, aware)
        insert_analysis_record(conn, none)
        query = text("SELECT created_at FROM analysis_records WHERE id = :i")
        assert conn.execute(query, {"i": aware.id}).scalar_one() == self.AWARE
        assert conn.execute(query, {"i": none.id}).scalar_one() is not None


def rejected(conn: Connection, **overrides: Any) -> None:
    with pytest.raises(IntegrityError), conn.begin_nested():
        insert_analysis_record(conn, make_record(**overrides))


def accepted(conn: Connection, **overrides: Any) -> None:
    with conn.begin_nested():
        insert_analysis_record(conn, make_record(**overrides))


class TestSignalIdsCheck:
    @pytest.mark.parametrize(
        "bad",
        [["Urgency"], ["has space"], ["a,b"], ["a" * 65], ["ok", "a" * 65], [""]],
    )
    def test_rejects(self, conn: Connection, bad: list[str]) -> None:
        rejected(conn, signal_ids=bad)

    @pytest.mark.parametrize(
        "good",
        [[], ["urgency"], ["urgency", "brand_lookalike_host"], ["a" * 64]],
    )
    def test_accepts(self, conn: Connection, good: list[str]) -> None:
        accepted(conn, signal_ids=good)


class TestFieldLength:
    @pytest.mark.parametrize("field", ["experiment_id", "variant"])
    def test_65_rejected_64_accepted(self, conn: Connection, field: str) -> None:
        rejected(conn, **{field: "x" * 65})
        accepted(conn, **{field: "x" * 64})


class TestClassifierPair:
    def test_label_without_score_rejected(self, conn: Connection) -> None:
        rejected(conn, classifier_label="scam_like", classifier_raw_score=None)

    def test_score_without_label_rejected(self, conn: Connection) -> None:
        rejected(conn, classifier_label=None, classifier_raw_score=0.5)

    def test_both_or_neither_accepted(self, conn: Connection) -> None:
        accepted(conn, classifier_label="scam_like", classifier_raw_score=0.5)
        accepted(conn, classifier_label=None, classifier_raw_score=None)


class TestScorePair:
    def test_score_with_type_none_rejected(self, conn: Connection) -> None:
        rejected(conn, risk_score=10, score_type="none")

    def test_null_score_with_heuristic_rejected(self, conn: Connection) -> None:
        rejected(conn, risk_score=None, score_type="heuristic")

    def test_valid_pairs_accepted(self, conn: Connection) -> None:
        accepted(conn, risk_score=10, score_type="heuristic")
        accepted(conn, risk_score=None, score_type="none")


class TestPrecision:
    def test_raw_score_round_trips_exactly(self, conn: Connection) -> None:
        value = 0.123456789012345
        rec = make_record(classifier_raw_score=value)
        insert_analysis_record(conn, rec)
        stored = conn.execute(
            text("SELECT classifier_raw_score FROM analysis_records WHERE id = :i"),
            {"i": rec.id},
        ).scalar_one()
        assert stored == value


class TestParametersHidden:
    def test_failed_statement_hides_parameters(self, conn: Connection) -> None:
        with pytest.raises(DBAPIError) as info:
            conn.execute(text("SELECT length(CAST(:s AS text)) / 0"), {"s": "secret-value"})
        assert "[parameters:" not in str(info.value)
        assert "secret-value" not in str(info.value)
