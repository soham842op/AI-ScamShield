from dataclasses import dataclass, field
from datetime import datetime
from enum import StrEnum
from typing import Any
from uuid import UUID

from sqlalchemy import Connection, delete, exists, insert, literal, or_, select
from sqlalchemy.dialects.postgresql import insert as pg_insert
from sqlalchemy.exc import IntegrityError

from app.db.models import AnalysisRecordRow, FeedbackRow, RateLimitCounterRow
from app.db.retention import (
    ANALYSIS_RECORD_RETENTION,
    FEEDBACK_RETENTION,
    RATE_LIMIT_RETENTION,
)

_FK_VIOLATION = "23503"


def _require_aware(value: datetime, name: str) -> None:
    # A naive datetime would be read in the session time zone and stored shifted.
    if value.tzinfo is None:
        raise ValueError(f"{name} must be timezone-aware")


@dataclass(frozen=True, slots=True)
class AnalysisRecord:
    id: UUID
    input_type: str
    channel: str | None
    char_count: int
    url_count: int
    classification: str
    risk_score: int | None
    score_type: str
    classifier_label: str | None
    classifier_raw_score: float | None
    signal_ids: list[str]
    url_check_status: str
    url_status_counts: dict[str, int]
    explanation_source: str
    versions: dict[str, Any]
    latency_ms: int
    timings_ms: dict[str, int] = field(default_factory=dict)
    experiment_id: str | None = None
    variant: str | None = None
    # None lets the database set it (now()).
    created_at: datetime | None = None


class FeedbackOutcome(StrEnum):
    CREATED = "created"
    UNKNOWN_REQUEST = "unknown_request"  # API: 404 not_found
    DUPLICATE = "duplicate"  # API: 409 conflict


@dataclass(frozen=True, slots=True)
class FeedbackResult:
    outcome: FeedbackOutcome
    # Set only when outcome is CREATED (the 201 response needs both).
    feedback_id: UUID | None = None
    created_at: datetime | None = None


@dataclass(frozen=True, slots=True)
class PurgeCounts:
    analysis_records: int
    feedback: int
    rate_limit_counters: int


def insert_analysis_record(conn: Connection, record: AnalysisRecord) -> None:
    values: dict[str, Any] = {
        "id": record.id,
        "input_type": record.input_type,
        "channel": record.channel,
        "char_count": record.char_count,
        "url_count": record.url_count,
        "classification": record.classification,
        "risk_score": record.risk_score,
        "score_type": record.score_type,
        "classifier_label": record.classifier_label,
        "classifier_raw_score": record.classifier_raw_score,
        "signal_ids": record.signal_ids,
        "url_check_status": record.url_check_status,
        "url_status_counts": record.url_status_counts,
        "explanation_source": record.explanation_source,
        "versions": record.versions,
        "experiment_id": record.experiment_id,
        "variant": record.variant,
        "latency_ms": record.latency_ms,
        "timings_ms": record.timings_ms,
    }
    if record.created_at is not None:
        _require_aware(record.created_at, "created_at")
        values["created_at"] = record.created_at
    conn.execute(insert(AnalysisRecordRow).values(**values))


def insert_feedback(
    conn: Connection, request_id: UUID, helpful: bool, verdict: str | None
) -> FeedbackResult:
    # One statement: insert only if the record exists, skip if feedback exists.
    # A purge that deletes the record between the SELECT and the commit makes the
    # foreign key fail (sqlstate 23503). That is mapped to unknown_request, using a
    # savepoint so the caller's transaction stays usable.
    stmt = (
        pg_insert(FeedbackRow)
        .from_select(
            ["request_id", "helpful", "verdict"],
            select(AnalysisRecordRow.id, literal(helpful), literal(verdict)).where(
                AnalysisRecordRow.id == request_id
            ),
        )
        .on_conflict_do_nothing(index_elements=["request_id"])
        .returning(FeedbackRow.id, FeedbackRow.created_at)
    )
    try:
        with conn.begin_nested():
            row = conn.execute(stmt).first()
    except IntegrityError as exc:
        if getattr(exc.orig, "sqlstate", None) == _FK_VIOLATION:
            return FeedbackResult(FeedbackOutcome.UNKNOWN_REQUEST)
        raise
    if row is not None:
        return FeedbackResult(FeedbackOutcome.CREATED, row.id, row.created_at)
    record_exists = conn.execute(
        select(exists().where(AnalysisRecordRow.id == request_id))
    ).scalar_one()
    outcome = FeedbackOutcome.DUPLICATE if record_exists else FeedbackOutcome.UNKNOWN_REQUEST
    return FeedbackResult(outcome)


def increment_rate_limit(conn: Connection, key: str, window_start: datetime) -> int:
    """Add one to the counter for (key, window_start) and return the new count.

    The upsert holds a row lock until the transaction ends. Call this in its own
    short transaction (``with engine.begin()``) and commit before any provider call.
    Never hold it open across I/O. ``window_start`` must be timezone-aware.
    """
    _require_aware(window_start, "window_start")
    stmt = (
        pg_insert(RateLimitCounterRow)
        .values(key=key, window_start=window_start, count=1)
        .on_conflict_do_update(
            index_elements=["key", "window_start"],
            set_={"count": RateLimitCounterRow.count + 1},
        )
        .returning(RateLimitCounterRow.count)
    )
    return int(conn.execute(stmt).scalar_one())


def purge_expired(conn: Connection, now: datetime) -> PurgeCounts:
    if now.tzinfo is None:
        raise ValueError("now must be timezone-aware")
    # Feedback is deleted explicitly, before its records, so the count is accurate:
    # rows past their own retention, and rows whose record is about to expire. The
    # foreign key cascade would remove the latter anyway. Feedback is created after
    # its record, so the record's period normally runs out first; the separate
    # created_at rule only matters if FEEDBACK_RETENTION is set shorter.
    record_cutoff = now - ANALYSIS_RECORD_RETENTION
    feedback = conn.execute(
        delete(FeedbackRow).where(
            or_(
                FeedbackRow.created_at < now - FEEDBACK_RETENTION,
                FeedbackRow.request_id.in_(
                    select(AnalysisRecordRow.id).where(AnalysisRecordRow.created_at < record_cutoff)
                ),
            )
        )
    ).rowcount
    records = conn.execute(
        delete(AnalysisRecordRow).where(AnalysisRecordRow.created_at < record_cutoff)
    ).rowcount
    counters = conn.execute(
        delete(RateLimitCounterRow).where(
            RateLimitCounterRow.window_start < now - RATE_LIMIT_RETENTION
        )
    ).rowcount
    return PurgeCounts(analysis_records=records, feedback=feedback, rate_limit_counters=counters)
