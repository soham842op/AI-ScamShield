"""Test doubles for the API layer. Nothing here touches a database or the network."""

from datetime import UTC, datetime
from uuid import UUID, uuid4

from app.core.services import Pipeline
from app.db.repository import AnalysisRecord, FeedbackOutcome, FeedbackResult
from app.pipeline.types import (
    AnalysisResult,
    ClassifierResult,
    Explanation,
    ParsedUrl,
    Signal,
    SubmittedUrl,
    UrlCheck,
    UrlEntry,
    UrlLookup,
    Versions,
)

NOT_A_GUARANTEE = (
    "A risk assessment is not a guarantee. A low rating is not proof that content is legitimate."
)


class FakePersistence:
    def __init__(self) -> None:
        self.records: list[AnalysisRecord] = []
        self.feedback: dict[UUID, tuple[bool, str | None]] = {}
        self.error: Exception | None = None

    async def save_analysis(self, record: AnalysisRecord) -> None:
        if self.error:
            raise self.error
        self.records.append(record)

    async def save_feedback(
        self, request_id: UUID, helpful: bool, verdict: str | None
    ) -> FeedbackResult:
        if self.error:
            raise self.error
        if request_id not in {r.id for r in self.records}:
            return FeedbackResult(FeedbackOutcome.UNKNOWN_REQUEST)
        if request_id in self.feedback:
            return FeedbackResult(FeedbackOutcome.DUPLICATE)
        self.feedback[request_id] = (helpful, verdict)
        return FeedbackResult(FeedbackOutcome.CREATED, uuid4(), datetime.now(UTC))


class RaisingLimiter:
    def __init__(self, error: Exception) -> None:
        self.error = error

    async def hit(self, scope: str, client: str, windows: object) -> object:
        raise self.error


def make_url_entry(
    status: str = "not_checked", reason: str | None = "provider_not_configured"
) -> UrlEntry:
    parsed = ParsedUrl(
        display="http://example.com/login",
        lookup="http://example.com/login",
        host_unicode="example.com",
        punycode=None,
        scheme_assumed=True,
    )
    threats = ("SOCIAL_ENGINEERING",) if status == "flagged" else ()
    return UrlEntry(parsed, UrlLookup(status=status, reason=reason, threat_types=threats))  # type: ignore[arg-type]


def make_result(input_type: str = "message", with_url: bool = True) -> AnalysisResult:
    entries = (make_url_entry(),) if with_url else ()
    check = UrlCheck(
        status="not_checked" if entries else "not_applicable",
        provider="none" if entries else None,
        checked_at=None,
        urls_found=len(entries),
        urls_truncated=False,
        urls=entries,
    )
    return AnalysisResult(
        input_type=input_type,  # type: ignore[arg-type]
        channel="sms" if input_type == "message" else None,
        char_count=42,
        classification="inconclusive",
        risk_score=None,
        score_type="none",
        score_basis=None,
        classifier=ClassifierResult(
            status="unavailable" if input_type == "message" else "not_applicable"
        ),
        signals=(
            Signal(
                "urgency", "rules", "medium", "The text pressures you to act quickly.", "act now"
            ),
        ),
        url_check=check,
        explanation=Explanation(
            text="There is not enough information to rate this.", source="template"
        ),
        recommendations=("Verify the sender through an official channel.",),
        limitations=(NOT_A_GUARANTEE,),
        versions=Versions(pipeline="test-1", rules="test-1"),
        timings_ms={"rules": 1},
    )


def fake_pipeline() -> Pipeline:
    async def message(text: str, channel: str, *, provider: object) -> AnalysisResult:
        return make_result("message")

    async def url(submitted: SubmittedUrl, char_count: int, *, provider: object) -> AnalysisResult:
        return make_result("url")

    return Pipeline(analyze_message=message, analyze_url=url)
