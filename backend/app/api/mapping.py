from collections import Counter
from datetime import UTC, datetime
from uuid import UUID

from app.db.repository import AnalysisRecord
from app.pipeline.types import AnalysisResult
from app.schemas.analysis import (
    AnalysisResponse,
    ClassifierOut,
    ExplanationOut,
    SignalOut,
    UrlCheckOut,
    UrlResultOut,
    VersionsOut,
)


def utc_millis(value: datetime) -> datetime:
    """UTC with millisecond precision. A naive value is taken to be UTC."""
    value = value.replace(tzinfo=UTC) if value.tzinfo is None else value.astimezone(UTC)
    return value.replace(microsecond=value.microsecond // 1000 * 1000)


def now_utc() -> datetime:
    return utc_millis(datetime.now(UTC))


def to_response(
    result: AnalysisResult, request_id: UUID, created_at: datetime, latency_ms: int
) -> AnalysisResponse:
    check = result.url_check
    return AnalysisResponse(
        schema_version="1.0",
        request_id=request_id,
        created_at=created_at,
        input_type=result.input_type,
        classification=result.classification,
        risk_score=result.risk_score,
        score_type=result.score_type,
        score_basis=result.score_basis,
        classifier=ClassifierOut(
            status=result.classifier.status,
            label=result.classifier.label,
            raw_score=result.classifier.raw_score,
        ),
        signals=[
            SignalOut(
                id=s.id,
                source=s.source,
                severity=s.severity,
                description=s.description,
                evidence_excerpt=s.evidence_excerpt,
            )
            for s in result.signals
        ],
        url_check=UrlCheckOut(
            status=check.status,
            provider=check.provider,
            checked_at=utc_millis(check.checked_at) if check.checked_at else None,
            urls_found=check.urls_found,
            urls_checked=check.urls_checked,
            urls_truncated=check.urls_truncated,
            urls=[
                UrlResultOut(
                    url=e.url.display,
                    host_unicode=e.url.host_unicode,
                    punycode=e.url.punycode,
                    scheme_assumed=e.url.scheme_assumed,
                    status=e.lookup.status,
                    reason=e.lookup.reason,
                    threat_types=list(e.lookup.threat_types),
                )
                for e in check.urls
            ],
        ),
        explanation=ExplanationOut(text=result.explanation.text, source=result.explanation.source),
        recommendations=list(result.recommendations),
        limitations=list(result.limitations),
        versions=VersionsOut(
            pipeline=result.versions.pipeline,
            rules=result.versions.rules,
            model=result.versions.model,
            prompt=result.versions.prompt,
        ),
        experiment=None,
        latency_ms=latency_ms,
    )


def to_record(
    result: AnalysisResult, request_id: UUID, created_at: datetime, latency_ms: int
) -> AnalysisRecord:
    """The stored record: ids, counts and versions only. No text, excerpts or URLs."""
    check = result.url_check
    counts = Counter(e.lookup.status for e in check.urls)
    return AnalysisRecord(
        id=request_id,
        input_type=result.input_type,
        channel=result.channel,
        char_count=result.char_count,
        url_count=1 if result.input_type == "url" else check.urls_found,
        classification=result.classification,
        risk_score=result.risk_score,
        score_type=result.score_type,
        classifier_label=result.classifier.label,
        classifier_raw_score=result.classifier.raw_score,
        signal_ids=[s.id for s in result.signals],
        url_check_status=check.status,
        url_status_counts={str(status): n for status, n in counts.items()},
        explanation_source=result.explanation.source,
        versions={
            "pipeline": result.versions.pipeline,
            "rules": result.versions.rules,
            "model": result.versions.model,
            "prompt": result.versions.prompt,
        },
        latency_ms=latency_ms,
        timings_ms=dict(result.timings_ms),
        created_at=created_at,
    )
