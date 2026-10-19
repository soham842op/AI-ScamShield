import uuid
from datetime import datetime
from typing import Any

from sqlalchemy import (
    TIMESTAMP,
    Boolean,
    CheckConstraint,
    Double,
    ForeignKey,
    Index,
    Integer,
    MetaData,
    SmallInteger,
    Text,
    UniqueConstraint,
    text,
)
from sqlalchemy.dialects.postgresql import ARRAY, JSONB, UUID
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column

NAMING_CONVENTION = {
    "ix": "ix_%(table_name)s_%(column_0_N_name)s",
    "uq": "uq_%(table_name)s_%(column_0_N_name)s",
    "ck": "ck_%(table_name)s_%(constraint_name)s",
    "fk": "fk_%(table_name)s_%(column_0_name)s_%(referred_table_name)s",
    "pk": "pk_%(table_name)s",
}

INPUT_TYPES = ("message", "url")
CHANNELS = ("sms", "email", "chat", "social", "other")
CLASSIFICATIONS = ("likely_legitimate", "suspicious", "high_risk", "inconclusive")
SCORE_TYPES = ("heuristic", "calibrated_probability", "none")
CLASSIFIER_LABELS = ("scam_like", "not_scam_like")
URL_CHECK_STATUSES = ("flagged", "no_match", "inconclusive", "not_checked", "not_applicable")
EXPLANATION_SOURCES = ("llm", "template")
VERDICTS = ("correct", "false_alarm", "missed_scam", "unsure")

TimestampTz = TIMESTAMP(timezone=True)

# The text form of a text[] quotes any element holding a comma, space, quote or brace,
# so this accepts only elements of 1 to 64 characters from [a-z0-9_].
SIGNAL_IDS_CHECK = r"signal_ids::text ~ '^\{([a-z0-9_]{1,64}(,[a-z0-9_]{1,64})*)?\}$'"


def _in_list(column: str, values: tuple[str, ...]) -> str:
    quoted = ", ".join(f"'{v}'" for v in values)
    return f"{column} IN ({quoted})"


class Base(DeclarativeBase):
    metadata = MetaData(naming_convention=NAMING_CONVENTION)


class AnalysisRecordRow(Base):
    __tablename__ = "analysis_records"
    __table_args__ = (
        CheckConstraint(_in_list("input_type", INPUT_TYPES), name="input_type"),
        CheckConstraint(
            f"channel IS NULL OR {_in_list('channel', CHANNELS)}",
            name="channel",
        ),
        CheckConstraint("(input_type = 'url') = (channel IS NULL)", name="channel_matches_input"),
        CheckConstraint(_in_list("classification", CLASSIFICATIONS), name="classification"),
        CheckConstraint(_in_list("score_type", SCORE_TYPES), name="score_type"),
        CheckConstraint(
            f"classifier_label IS NULL OR {_in_list('classifier_label', CLASSIFIER_LABELS)}",
            name="classifier_label",
        ),
        CheckConstraint(_in_list("url_check_status", URL_CHECK_STATUSES), name="url_check_status"),
        CheckConstraint(
            _in_list("explanation_source", EXPLANATION_SOURCES), name="explanation_source"
        ),
        CheckConstraint("risk_score IS NULL OR risk_score BETWEEN 0 AND 100", name="risk_score"),
        CheckConstraint(
            "classifier_raw_score IS NULL OR classifier_raw_score BETWEEN 0 AND 1",
            name="classifier_raw_score",
        ),
        # The classifier label and raw score are set together, and a score exists
        # exactly when the score type is not "none".
        CheckConstraint(
            "(classifier_label IS NULL) = (classifier_raw_score IS NULL)", name="classifier_pair"
        ),
        CheckConstraint("(risk_score IS NULL) = (score_type = 'none')", name="score_pair"),
        # Free-form columns are limited to short identifiers, not content.
        CheckConstraint(SIGNAL_IDS_CHECK, name="signal_ids"),
        CheckConstraint(
            "experiment_id IS NULL OR length(experiment_id) <= 64", name="experiment_id"
        ),
        CheckConstraint("variant IS NULL OR length(variant) <= 64", name="variant"),
        CheckConstraint("char_count >= 0", name="char_count"),
        CheckConstraint("url_count >= 0", name="url_count"),
        CheckConstraint("latency_ms >= 0", name="latency_ms"),
        Index("ix_analysis_records_created_at", "created_at"),
    )

    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True)
    created_at: Mapped[datetime] = mapped_column(
        TimestampTz, nullable=False, server_default=text("now()")
    )
    input_type: Mapped[str] = mapped_column(Text, nullable=False)
    channel: Mapped[str | None] = mapped_column(Text, nullable=True)
    char_count: Mapped[int] = mapped_column(Integer, nullable=False)
    url_count: Mapped[int] = mapped_column(Integer, nullable=False)
    classification: Mapped[str] = mapped_column(Text, nullable=False)
    risk_score: Mapped[int | None] = mapped_column(SmallInteger, nullable=True)
    score_type: Mapped[str] = mapped_column(Text, nullable=False)
    classifier_label: Mapped[str | None] = mapped_column(Text, nullable=True)
    classifier_raw_score: Mapped[float | None] = mapped_column(Double, nullable=True)
    signal_ids: Mapped[list[str]] = mapped_column(
        ARRAY(Text), nullable=False, server_default=text("'{}'::text[]")
    )
    url_check_status: Mapped[str] = mapped_column(Text, nullable=False)
    url_status_counts: Mapped[dict[str, Any]] = mapped_column(
        JSONB, nullable=False, server_default=text("'{}'::jsonb")
    )
    explanation_source: Mapped[str] = mapped_column(Text, nullable=False)
    versions: Mapped[dict[str, Any]] = mapped_column(JSONB, nullable=False)
    experiment_id: Mapped[str | None] = mapped_column(Text, nullable=True)
    variant: Mapped[str | None] = mapped_column(Text, nullable=True)
    latency_ms: Mapped[int] = mapped_column(Integer, nullable=False)
    timings_ms: Mapped[dict[str, Any]] = mapped_column(
        JSONB, nullable=False, server_default=text("'{}'::jsonb")
    )


class FeedbackRow(Base):
    __tablename__ = "feedback"
    __table_args__ = (
        UniqueConstraint("request_id", name="uq_feedback_request_id"),
        CheckConstraint(
            f"verdict IS NULL OR {_in_list('verdict', VERDICTS)}",
            name="verdict",
        ),
        Index("ix_feedback_created_at", "created_at"),
    )

    id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), primary_key=True, server_default=text("gen_random_uuid()")
    )
    request_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("analysis_records.id", ondelete="CASCADE"),
        nullable=False,
    )
    created_at: Mapped[datetime] = mapped_column(
        TimestampTz, nullable=False, server_default=text("now()")
    )
    helpful: Mapped[bool] = mapped_column(Boolean, nullable=False)
    verdict: Mapped[str | None] = mapped_column(Text, nullable=True)


class RateLimitCounterRow(Base):
    __tablename__ = "rate_limit_counters"
    __table_args__ = (
        CheckConstraint("count >= 1", name="count"),
        Index("ix_rate_limit_counters_window_start", "window_start"),
    )

    key: Mapped[str] = mapped_column(Text, primary_key=True)
    window_start: Mapped[datetime] = mapped_column(TimestampTz, primary_key=True)
    count: Mapped[int] = mapped_column(Integer, nullable=False)
