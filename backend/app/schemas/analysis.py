from typing import Any, Literal
from uuid import UUID

from pydantic import BaseModel, ConfigDict, Field, field_validator

from app.pipeline.types import (
    Channel,
    Classification,
    ClassifierLabel,
    ClassifierStatus,
    ExplanationSource,
    InputType,
    ScoreBasis,
    ScoreType,
    Severity,
    SignalSource,
    UrlCheckStatus,
    UrlReason,
    UrlStatus,
)
from app.schemas.validation import UtcTimestamp, clean_text, clean_url, require_str

SCHEMA_VERSION = "1.0"


class MessageAnalysisRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    text: str = Field(min_length=1, max_length=10000)
    channel: Channel = "other"

    @field_validator("text", mode="before")
    @classmethod
    def _check_text(cls, value: Any) -> str:
        return clean_text(value)

    @field_validator("channel", mode="before")
    @classmethod
    def _check_channel(cls, value: Any) -> str:
        return require_str(value)


class UrlAnalysisRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    url: str = Field(min_length=1, max_length=2048)

    @field_validator("url", mode="before")
    @classmethod
    def _check_url(cls, value: Any) -> str:
        return clean_url(value)


class ClassifierOut(BaseModel):
    status: ClassifierStatus
    label: ClassifierLabel | None
    raw_score: float | None = Field(ge=0.0, le=1.0)


class SignalOut(BaseModel):
    id: str
    source: SignalSource
    severity: Severity
    description: str
    evidence_excerpt: str | None


class UrlResultOut(BaseModel):
    url: str
    host_unicode: str
    punycode: str | None
    scheme_assumed: bool
    status: UrlStatus
    reason: UrlReason | None
    threat_types: list[str]


class UrlCheckOut(BaseModel):
    status: UrlCheckStatus
    provider: str | None
    checked_at: UtcTimestamp | None
    urls_found: int = Field(ge=0)
    urls_checked: int = Field(ge=0)
    urls_truncated: bool
    urls: list[UrlResultOut]


class ExplanationOut(BaseModel):
    text: str
    source: ExplanationSource


class VersionsOut(BaseModel):
    pipeline: str
    rules: str
    model: str | None
    prompt: str | None


class ExperimentOut(BaseModel):
    id: str
    variant: str


class AnalysisResponse(BaseModel):
    schema_version: Literal["1.0"]
    request_id: UUID
    created_at: UtcTimestamp
    input_type: InputType
    classification: Classification
    risk_score: int | None = Field(ge=0, le=100)
    score_type: ScoreType
    score_basis: ScoreBasis | None
    classifier: ClassifierOut
    signals: list[SignalOut]
    url_check: UrlCheckOut
    explanation: ExplanationOut
    recommendations: list[str]
    limitations: list[str]
    versions: VersionsOut
    experiment: ExperimentOut | None
    latency_ms: int = Field(ge=0)
