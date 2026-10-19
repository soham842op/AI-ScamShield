"""Template explanation built only from structured evidence.

The evidence type carries no submitted text, URLs or hosts, so none can appear
here. Every sentence comes from the fixed vocabulary below or from a signal
description supplied by the rules modules.
"""

from app.pipeline.types import (
    Classification,
    EvidenceSignal,
    ExplanationEvidence,
    Severity,
    UrlCheckStatus,
)

TEMPLATE_VERSION = "tpl-1.1"

MAX_SENTENCES = 3
MAX_SIGNALS_SHOWN = 2

_LEAD: dict[Classification, str] = {
    "high_risk": "This looks like a scam.",
    "suspicious": "This has warning signs of a scam.",
    "likely_legitimate": (
        "No common scam warning signs were found, but that does not prove it is legitimate."
    ),
    "inconclusive": "There is not enough information to rate this.",
}

_URL_PHRASE: dict[UrlCheckStatus, str | None] = {
    "not_checked": "The links were not checked against a reputation service.",
    "inconclusive": "Some links could not be checked.",
    "flagged": "A link was flagged by the URL reputation provider.",
    "no_match": (
        "The links were not found on the reputation list, which does not mean they are safe."
    ),
    "not_applicable": None,
}

# The URL endpoint always has exactly one link, so it gets singular wording.
_URL_PHRASE_SINGLE: dict[UrlCheckStatus, str | None] = {
    "not_checked": "The link was not checked against a reputation service.",
    "inconclusive": "The link could not be checked.",
    "flagged": "The link was flagged by the URL reputation provider.",
    "no_match": ("The link was not found on the reputation list, which does not mean it is safe."),
    "not_applicable": None,
}

_SIGNALS_PREFIX = "Main warning signs:"
_MODEL_UNAVAILABLE = "The text model is not available, so only rule checks were used."

_SEVERITY_RANK: dict[Severity, int] = {"high": 0, "medium": 1, "low": 2}


def _top_signals(signals: tuple[EvidenceSignal, ...]) -> list[EvidenceSignal]:
    # URL reputation is covered by the URL status sentence, so skip it here.
    # sorted() is stable: ties keep the order the caller gave.
    candidates = [s for s in signals if s.source != "url_reputation"]
    ranked = sorted(candidates, key=lambda s: _SEVERITY_RANK[s.severity])
    return ranked[:MAX_SIGNALS_SHOWN]


def _signals_sentence(signals: tuple[EvidenceSignal, ...]) -> str | None:
    top = _top_signals(signals)
    if not top:
        return None
    parts = [s.description.strip().rstrip(".") for s in top]
    return f"{_SIGNALS_PREFIX} " + "; ".join(parts) + "."


def template_explanation(evidence: ExplanationEvidence) -> str:
    phrases = _URL_PHRASE_SINGLE if evidence.input_type == "url" else _URL_PHRASE
    sentences: list[str | None] = [
        _LEAD[evidence.classification],
        _signals_sentence(evidence.signals),
        phrases[evidence.url_check_status],
    ]
    # Only the unrated case needs the reason spelled out.
    if (
        evidence.classification == "inconclusive"
        and evidence.input_type == "message"
        and evidence.classifier_status == "unavailable"
    ):
        sentences.append(_MODEL_UNAVAILABLE)
    chosen = [s for s in sentences if s][:MAX_SENTENCES]
    return " ".join(chosen)
