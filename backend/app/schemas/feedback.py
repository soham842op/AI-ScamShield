from typing import Any, Literal
from uuid import UUID

from pydantic import BaseModel, ConfigDict, StrictBool, field_validator

from app.schemas.validation import UtcTimestamp, require_str

Verdict = Literal["correct", "false_alarm", "missed_scam", "unsure"]


class FeedbackRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    request_id: UUID
    helpful: StrictBool
    verdict: Verdict | None = None

    @field_validator("request_id", mode="before")
    @classmethod
    def _check_request_id(cls, value: Any) -> str:
        return require_str(value)

    @field_validator("verdict", mode="before")
    @classmethod
    def _check_verdict(cls, value: Any) -> str | None:
        # Omitted and null mean the same.
        return None if value is None else require_str(value)


class FeedbackResponse(BaseModel):
    feedback_id: UUID
    received_at: UtcTimestamp
