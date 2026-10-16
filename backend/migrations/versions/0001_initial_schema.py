"""Create analysis_records, feedback and rate_limit_counters.

Revision ID: 0001
Revises:
Create Date: 2026-10-16
"""

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql

revision: str = "0001"
down_revision: str | None = None
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.create_table(
        "analysis_records",
        sa.Column("id", sa.UUID(), nullable=False),
        sa.Column(
            "created_at",
            sa.TIMESTAMP(timezone=True),
            server_default=sa.text("now()"),
            nullable=False,
        ),
        sa.Column("input_type", sa.Text(), nullable=False),
        sa.Column("channel", sa.Text(), nullable=True),
        sa.Column("char_count", sa.Integer(), nullable=False),
        sa.Column("url_count", sa.Integer(), nullable=False),
        sa.Column("classification", sa.Text(), nullable=False),
        sa.Column("risk_score", sa.SmallInteger(), nullable=True),
        sa.Column("score_type", sa.Text(), nullable=False),
        sa.Column("classifier_label", sa.Text(), nullable=True),
        sa.Column("classifier_raw_score", sa.Double(), nullable=True),
        sa.Column(
            "signal_ids",
            postgresql.ARRAY(sa.Text()),
            server_default=sa.text("'{}'::text[]"),
            nullable=False,
        ),
        sa.Column("url_check_status", sa.Text(), nullable=False),
        sa.Column(
            "url_status_counts",
            postgresql.JSONB(astext_type=sa.Text()),
            server_default=sa.text("'{}'::jsonb"),
            nullable=False,
        ),
        sa.Column("explanation_source", sa.Text(), nullable=False),
        sa.Column("versions", postgresql.JSONB(astext_type=sa.Text()), nullable=False),
        sa.Column("experiment_id", sa.Text(), nullable=True),
        sa.Column("variant", sa.Text(), nullable=True),
        sa.Column("latency_ms", sa.Integer(), nullable=False),
        sa.Column(
            "timings_ms",
            postgresql.JSONB(astext_type=sa.Text()),
            server_default=sa.text("'{}'::jsonb"),
            nullable=False,
        ),
        sa.CheckConstraint(
            "(input_type = 'url') = (channel IS NULL)",
            name=op.f("ck_analysis_records_channel_matches_input"),
        ),
        sa.CheckConstraint(
            "channel IS NULL OR channel IN ('sms', 'email', 'chat', 'social', 'other')",
            name=op.f("ck_analysis_records_channel"),
        ),
        sa.CheckConstraint(
            "classification IN ('likely_legitimate', 'suspicious', 'high_risk', 'inconclusive')",
            name=op.f("ck_analysis_records_classification"),
        ),
        sa.CheckConstraint(
            "classifier_label IS NULL OR classifier_label IN ('scam_like', 'not_scam_like')",
            name=op.f("ck_analysis_records_classifier_label"),
        ),
        sa.CheckConstraint(
            "explanation_source IN ('llm', 'template')",
            name=op.f("ck_analysis_records_explanation_source"),
        ),
        sa.CheckConstraint(
            "input_type IN ('message', 'url')", name=op.f("ck_analysis_records_input_type")
        ),
        sa.CheckConstraint(
            "score_type IN ('heuristic', 'calibrated_probability', 'none')",
            name=op.f("ck_analysis_records_score_type"),
        ),
        sa.CheckConstraint(
            "url_check_status IN "
            "('flagged', 'no_match', 'inconclusive', 'not_checked', 'not_applicable')",
            name=op.f("ck_analysis_records_url_check_status"),
        ),
        sa.CheckConstraint(
            "(classifier_label IS NULL) = (classifier_raw_score IS NULL)",
            name=op.f("ck_analysis_records_classifier_pair"),
        ),
        sa.CheckConstraint(
            "(risk_score IS NULL) = (score_type = 'none')",
            name=op.f("ck_analysis_records_score_pair"),
        ),
        sa.CheckConstraint(
            r"signal_ids::text ~ '^\{([a-z0-9_]{1,64}(,[a-z0-9_]{1,64})*)?\}$'",
            name=op.f("ck_analysis_records_signal_ids"),
        ),
        sa.CheckConstraint(
            "experiment_id IS NULL OR length(experiment_id) <= 64",
            name=op.f("ck_analysis_records_experiment_id"),
        ),
        sa.CheckConstraint(
            "variant IS NULL OR length(variant) <= 64",
            name=op.f("ck_analysis_records_variant"),
        ),
        sa.CheckConstraint("char_count >= 0", name=op.f("ck_analysis_records_char_count")),
        sa.CheckConstraint(
            "classifier_raw_score IS NULL OR classifier_raw_score BETWEEN 0 AND 1",
            name=op.f("ck_analysis_records_classifier_raw_score"),
        ),
        sa.CheckConstraint("latency_ms >= 0", name=op.f("ck_analysis_records_latency_ms")),
        sa.CheckConstraint(
            "risk_score IS NULL OR risk_score BETWEEN 0 AND 100",
            name=op.f("ck_analysis_records_risk_score"),
        ),
        sa.CheckConstraint("url_count >= 0", name=op.f("ck_analysis_records_url_count")),
        sa.PrimaryKeyConstraint("id", name=op.f("pk_analysis_records")),
    )
    op.create_index(
        "ix_analysis_records_created_at", "analysis_records", ["created_at"], unique=False
    )
    op.create_table(
        "rate_limit_counters",
        sa.Column("key", sa.Text(), nullable=False),
        sa.Column("window_start", sa.TIMESTAMP(timezone=True), nullable=False),
        sa.Column("count", sa.Integer(), nullable=False),
        sa.CheckConstraint("count >= 1", name=op.f("ck_rate_limit_counters_count")),
        sa.PrimaryKeyConstraint("key", "window_start", name=op.f("pk_rate_limit_counters")),
    )
    op.create_index(
        "ix_rate_limit_counters_window_start", "rate_limit_counters", ["window_start"], unique=False
    )
    op.create_table(
        "feedback",
        sa.Column("id", sa.UUID(), server_default=sa.text("gen_random_uuid()"), nullable=False),
        sa.Column("request_id", sa.UUID(), nullable=False),
        sa.Column(
            "created_at",
            sa.TIMESTAMP(timezone=True),
            server_default=sa.text("now()"),
            nullable=False,
        ),
        sa.Column("helpful", sa.Boolean(), nullable=False),
        sa.Column("verdict", sa.Text(), nullable=True),
        sa.CheckConstraint(
            "verdict IS NULL OR verdict IN ('correct', 'false_alarm', 'missed_scam', 'unsure')",
            name=op.f("ck_feedback_verdict"),
        ),
        sa.ForeignKeyConstraint(
            ["request_id"],
            ["analysis_records.id"],
            name=op.f("fk_feedback_request_id_analysis_records"),
            ondelete="CASCADE",
        ),
        sa.PrimaryKeyConstraint("id", name=op.f("pk_feedback")),
        sa.UniqueConstraint("request_id", name="uq_feedback_request_id"),
    )
    op.create_index("ix_feedback_created_at", "feedback", ["created_at"], unique=False)


def downgrade() -> None:
    op.drop_index("ix_feedback_created_at", table_name="feedback")
    op.drop_table("feedback")
    op.drop_index("ix_rate_limit_counters_window_start", table_name="rate_limit_counters")
    op.drop_table("rate_limit_counters")
    op.drop_index("ix_analysis_records_created_at", table_name="analysis_records")
    op.drop_table("analysis_records")
