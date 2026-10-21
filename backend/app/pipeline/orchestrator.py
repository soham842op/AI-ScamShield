"""Runs the analysis pipeline for a message or a single URL."""

import logging
import time
import unicodedata
from collections.abc import Sequence
from datetime import UTC, datetime

from app.pipeline.aggregator import (
    Thresholds,
    build_url_check,
    classify,
    merge_signals,
    risk_score,
    url_reputation_signal,
)
from app.pipeline.catalog import build_limitations, build_recommendations
from app.pipeline.explain import TEMPLATE_VERSION, explain, template_explanation
from app.pipeline.intel import UrlReputationProvider
from app.pipeline.normalize import normalize
from app.pipeline.rules import RULES_VERSION
from app.pipeline.rules import evaluate as evaluate_rules
from app.pipeline.types import (
    AnalysisResult,
    Channel,
    ClassifierResult,
    EvidenceSignal,
    EvidenceUrl,
    Explanation,
    ExplanationEvidence,
    InputType,
    LookupBatch,
    ParsedUrl,
    Signal,
    SubmittedUrl,
    UrlCheck,
    UrlEntry,
    UrlLookup,
    UrlReason,
    Versions,
)
from app.pipeline.urls import URL_RULES_VERSION, extract_urls

PIPELINE_VERSION = "1.0.0"

_FALLBACK_EXPLANATION = "This result is based on automated checks and may be incomplete."

_log = logging.getLogger(__name__)


def _elapsed_ms(start: float) -> int:
    return round((time.perf_counter() - start) * 1000)


def _clean_lookup(lookup: UrlLookup) -> UrlLookup:
    """Keep provider output within the response invariants."""
    if lookup.status in ("flagged", "no_match"):
        threats = lookup.threat_types if lookup.status == "flagged" else ()
        if lookup.status == "flagged" and not threats:
            threats = ("UNSPECIFIED",)
        return UrlLookup(status=lookup.status, reason=None, threat_types=threats)
    if lookup.status == "unknown":
        failed = lookup.reason if lookup.reason in ("provider_timeout", "provider_error") else None
        return UrlLookup(status="unknown", reason=failed or "provider_error")
    skipped = (
        lookup.reason if lookup.reason in ("provider_not_configured", "quota_exhausted") else None
    )
    return UrlLookup(status="not_checked", reason=skipped or "provider_not_configured")


async def _lookup(
    provider: UrlReputationProvider, urls: Sequence[ParsedUrl]
) -> tuple[tuple[UrlLookup, ...], datetime | None]:
    """Look the URLs up. A provider failure becomes `unknown` results, never an exception."""
    try:
        batch: LookupBatch = await provider.lookup(urls)
        if len(batch.results) != len(urls):
            raise ValueError("provider returned a different number of results")
        results = tuple(_clean_lookup(r) for r in batch.results)
    except Exception as exc:
        # Type only: the message could contain a submitted URL.
        _log.warning("url lookup failed: %s", type(exc).__name__)
        error: UrlReason = "provider_timeout" if isinstance(exc, TimeoutError) else "provider_error"
        return tuple(UrlLookup(status="unknown", reason=error) for _ in urls), None
    return results, batch.checked_at


async def _explain(evidence: ExplanationEvidence) -> Explanation:
    try:
        return await explain(evidence)
    except Exception as exc:
        _log.warning("explanation failed: %s", type(exc).__name__)
    try:
        return Explanation(text=template_explanation(evidence), source="template")
    except Exception as exc:
        _log.warning("template explanation failed: %s", type(exc).__name__)
    return Explanation(text=_FALLBACK_EXPLANATION, source="template")


async def _finish(
    *,
    input_type: InputType,
    channel: Channel | None,
    char_count: int,
    classifier: ClassifierResult,
    signals: Sequence[Signal],
    urls: Sequence[ParsedUrl],
    urls_found: int,
    truncated: bool,
    provider: UrlReputationProvider,
    timings: dict[str, int],
    thresholds: Thresholds | None = None,
) -> AnalysisResult:
    entries: tuple[UrlEntry, ...] = ()
    checked_at: datetime | None = None
    if urls:
        start = time.perf_counter()
        results, checked_at = await _lookup(provider, urls)
        timings["intel"] = _elapsed_ms(start)
        entries = tuple(UrlEntry(url=u, lookup=r) for u, r in zip(urls, results, strict=True))
        if checked_at is None and any(r.status in ("flagged", "no_match") for r in results):
            checked_at = datetime.now(UTC)

    url_check: UrlCheck = build_url_check(
        entries,
        urls_found=urls_found,
        truncated=truncated,
        provider=provider.provider_id,
        checked_at=checked_at,
    )

    all_signals = list(signals)
    reputation = url_reputation_signal(input_type, url_check)
    if reputation is not None:
        all_signals.append(reputation)
    final_signals = merge_signals(all_signals)

    classification = classify(
        input_type=input_type,
        classifier=classifier,
        signals=final_signals,
        url_check=url_check,
        thresholds=thresholds,
    )
    score, score_type, score_basis = risk_score(
        input_type=input_type, classifier=classifier, classification=classification
    )

    evidence = ExplanationEvidence(
        input_type=input_type,
        classification=classification,
        classifier_status=classifier.status,
        signals=tuple(
            EvidenceSignal(id=s.id, source=s.source, severity=s.severity, description=s.description)
            for s in final_signals
        ),
        url_check_status=url_check.status,
        urls=tuple(
            EvidenceUrl(
                status=e.lookup.status,
                reason=e.lookup.reason,
                threat_types=e.lookup.threat_types,
            )
            for e in url_check.urls
        ),
        urls_truncated=url_check.urls_truncated,
    )
    start = time.perf_counter()
    explanation = await _explain(evidence)
    timings["explain"] = _elapsed_ms(start)

    return AnalysisResult(
        input_type=input_type,
        channel=channel,
        char_count=char_count,
        classification=classification,
        risk_score=score,
        score_type=score_type,
        score_basis=score_basis,
        classifier=classifier,
        signals=final_signals,
        url_check=url_check,
        explanation=explanation,
        recommendations=build_recommendations(classification, (s.id for s in final_signals)),
        limitations=build_limitations(
            input_type=input_type,
            classification=classification,
            classifier_status=classifier.status,
            url_check=url_check,
        ),
        versions=Versions(
            pipeline=f"{PIPELINE_VERSION}+{TEMPLATE_VERSION}",
            rules=f"{RULES_VERSION}+{URL_RULES_VERSION}",
            model=None,
            prompt=explanation.prompt_version,
        ),
        timings_ms=timings,
    )


async def analyze_message(
    text: str, channel: Channel, *, provider: UrlReputationProvider
) -> AnalysisResult:
    timings: dict[str, int] = {}

    start = time.perf_counter()
    normalized = normalize(text)
    rule_signals = evaluate_rules(normalized)
    timings["rules"] = _elapsed_ms(start)

    start = time.perf_counter()
    extraction = extract_urls(normalized.display)
    timings["urls"] = _elapsed_ms(start)

    return await _finish(
        input_type="message",
        channel=channel,
        char_count=len(unicodedata.normalize("NFC", text)),
        # No text model yet: the result is rules and URL checks only.
        classifier=ClassifierResult(status="unavailable"),
        signals=(*rule_signals, *extraction.signals),
        urls=extraction.urls,
        urls_found=extraction.urls_found,
        truncated=extraction.truncated,
        provider=provider,
        timings=timings,
    )


async def analyze_url(
    submitted: SubmittedUrl, char_count: int, *, provider: UrlReputationProvider
) -> AnalysisResult:
    return await _finish(
        input_type="url",
        channel=None,
        char_count=char_count,
        classifier=ClassifierResult(status="not_applicable"),
        signals=submitted.signals,
        urls=(submitted.url,),
        urls_found=1,
        truncated=False,
        provider=provider,
        timings={},
    )
