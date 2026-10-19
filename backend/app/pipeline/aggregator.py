"""Deterministic aggregation: URL check status, classification and score.

Everything here is a pure function of its arguments.
"""

from collections.abc import Iterable, Sequence
from dataclasses import dataclass
from datetime import datetime

from app.pipeline.types import (
    Classification,
    ClassifierResult,
    InputType,
    ScoreBasis,
    ScoreType,
    Severity,
    Signal,
    SignalSource,
    UrlCheck,
    UrlCheckStatus,
    UrlEntry,
)

_SEVERITY_RANK: dict[Severity, int] = {"high": 0, "medium": 1, "low": 2}
_SOURCE_RANK: dict[SignalSource, int] = {
    "rules": 0,
    "classifier": 1,
    "url_rules": 2,
    "url_reputation": 3,
}

CLASSIFIER_SIGNAL_ID = "classifier_scam_like"
URL_REPUTATION_SIGNAL_ID = "url_reputation_flagged"


@dataclass(frozen=True, slots=True)
class Thresholds:
    """Classifier score cut-offs, with `suspicious < high_risk`."""

    suspicious: float
    high_risk: float

    def __post_init__(self) -> None:
        if not 0.0 <= self.suspicious < self.high_risk <= 1.0:
            raise ValueError("thresholds must satisfy 0 <= suspicious < high_risk <= 1")


def url_check_status(
    entries: Sequence[UrlEntry], *, urls_found: int, truncated: bool
) -> UrlCheckStatus:
    if urls_found == 0:
        return "not_applicable"
    statuses = [entry.lookup.status for entry in entries]
    if "flagged" in statuses:
        return "flagged"
    if statuses and all(s == "no_match" for s in statuses) and not truncated:
        return "no_match"
    if statuses and all(s == "not_checked" for s in statuses):
        return "not_checked"
    return "inconclusive"


def build_url_check(
    entries: Sequence[UrlEntry],
    *,
    urls_found: int,
    truncated: bool,
    provider: str,
    checked_at: datetime | None,
) -> UrlCheck:
    """Assemble the `url_check` object.

    `provider` is the provider id used for the lookup. It is dropped when there
    were no URLs, and `checked_at` is kept only if some URL was actually checked.
    """
    check = UrlCheck(
        status=url_check_status(entries, urls_found=urls_found, truncated=truncated),
        provider=provider if urls_found > 0 else None,
        checked_at=None,
        urls_found=urls_found,
        urls_truncated=truncated,
        urls=tuple(entries),
    )
    if check.urls_checked == 0:
        return check
    return UrlCheck(
        status=check.status,
        provider=check.provider,
        checked_at=checked_at,
        urls_found=urls_found,
        urls_truncated=truncated,
        urls=check.urls,
    )


def url_reputation_signal(input_type: InputType, url_check: UrlCheck) -> Signal | None:
    if url_check.status != "flagged":
        return None
    description = (
        "A link in the message was flagged by the URL reputation provider."
        if input_type == "message"
        else "The link was flagged by the URL reputation provider."
    )
    return Signal(
        id=URL_REPUTATION_SIGNAL_ID,
        source="url_reputation",
        severity="high",
        description=description,
        evidence_excerpt=None,
    )


def classifier_signal(classifier: ClassifierResult, thresholds: Thresholds | None) -> Signal | None:
    """Signal for a scam-like classifier score. Display and explanation only."""
    if classifier.status != "ok":
        return None
    if thresholds is None:
        raise ValueError("classifier thresholds are required when the classifier is ok")
    raw = _require_score(classifier, thresholds)
    if raw < thresholds.suspicious:
        return None
    return Signal(
        id=CLASSIFIER_SIGNAL_ID,
        source="classifier",
        severity="high" if raw >= thresholds.high_risk else "medium",
        description="The text model rates this message as similar to known scam messages.",
        evidence_excerpt=None,
    )


def _require_score(classifier: ClassifierResult, thresholds: Thresholds | None) -> float:
    if thresholds is None:
        raise ValueError("classifier thresholds are required when the classifier is ok")
    if classifier.raw_score is None:
        raise ValueError("classifier raw_score is required when the classifier is ok")
    return classifier.raw_score


def classify(
    *,
    input_type: InputType,
    classifier: ClassifierResult,
    signals: Iterable[Signal],
    url_check: UrlCheck,
    thresholds: Thresholds | None = None,
) -> Classification:
    raw: float | None = None
    if classifier.status == "ok":
        raw = _require_score(classifier, thresholds)

    # The classifier signal is display-only, so it never counts toward these clauses.
    counted = [s for s in signals if s.id != CLASSIFIER_SIGNAL_ID]
    high = sum(1 for s in counted if s.severity == "high")
    medium = sum(1 for s in counted if s.severity == "medium")

    if thresholds is not None and raw is not None:
        if url_check.status == "flagged" or raw >= thresholds.high_risk or high >= 2:
            return "high_risk"
        if raw >= thresholds.suspicious or high >= 1 or medium >= 2:
            return "suspicious"
    else:
        if url_check.status == "flagged" or high >= 2:
            return "high_risk"
        if high >= 1 or medium >= 2:
            return "suspicious"

    classifier_done = input_type == "url" or classifier.status == "ok"
    urls_done = url_check.status in ("not_applicable", "no_match")
    if classifier_done and urls_done and high == 0 and medium == 0:
        return "likely_legitimate"
    return "inconclusive"


def risk_score(
    *, input_type: InputType, classifier: ClassifierResult, classification: Classification
) -> tuple[int | None, ScoreType, ScoreBasis | None]:
    if (
        input_type == "message"
        and classifier.status == "ok"
        and classifier.raw_score is not None
        and classification != "inconclusive"
    ):
        return round(100 * classifier.raw_score), "heuristic", "text_classifier"
    return None, "none", None


def merge_signals(signals: Iterable[Signal]) -> tuple[Signal, ...]:
    """One signal per id (highest severity, first on a tie), in display order."""
    best: dict[str, Signal] = {}
    for signal in signals:
        current = best.get(signal.id)
        if current is None or _SEVERITY_RANK[signal.severity] < _SEVERITY_RANK[current.severity]:
            best[signal.id] = signal
    return tuple(
        sorted(
            best.values(),
            key=lambda s: (_SEVERITY_RANK[s.severity], _SOURCE_RANK[s.source], s.id),
        )
    )
